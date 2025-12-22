const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { prisma } = require('../config/database');

const router = express.Router();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Helper to generate JWT
const generateJwt = (user) =>
  jwt.sign(
    { userId: user.id, username: user.username, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );

// Register endpoint (local provider)
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: 'Username, email, and password are required' });
    }

    // Check if user already exists (by username or email)
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
      select: { id: true },
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await prisma.$transaction(async (tx) => {
      // Insert into users
      const user = await tx.user.create({
        data: {
          email,
          username,
        },
        select: {
          id: true,
          username: true,
          email: true,
          createdAt: true,
        },
      });

      // Insert into auth_providers for local provider
      await tx.authProvider.create({
        data: {
          userId: user.id,
          providerType: 'local',
          passwordHash: hashedPassword,
        },
      });

      return user;
    });

    const token = generateJwt(result);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: result.id,
        username: result.username,
        email: result.email,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint (local provider)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        username: true,
        email: true,
      },
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Get local auth provider for this user
    const localProvider = await prisma.authProvider.findFirst({
      where: {
        userId: user.id,
        providerType: 'local',
      },
      select: {
        passwordHash: true,
      },
    });

    if (!localProvider || !localProvider.passwordHash) {
      return res.status(401).json({
        error:
          'This account is not configured for email/password login. Please use Google login.',
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(
      password,
      localProvider.passwordHash
    );

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateJwt(user);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user (protected route)
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        username: true,
        email: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ error: 'Token expired' });
    }
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Google Login endpoint (google provider)
router.post('/google', async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ error: 'Google ID token is required' });
    }

    // Verify the Google ID token
    let ticket;
    try {
      ticket = await client.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
    } catch (error) {
      console.error('Google token verification error:', error);
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    if (!email) {
      return res.status(400).json({ error: 'Email not provided by Google' });
    }

    const user = await prisma.$transaction(async (tx) => {
      // 1. Try to find user by existing google auth_provider
      const existingGoogleProvider = await tx.authProvider.findFirst({
        where: {
          providerType: 'google',
          providerUserId: googleId,
        },
        include: {
          user: {
            select: {
              id: true,
              username: true,
              email: true,
            },
          },
        },
      });

      if (existingGoogleProvider?.user) {
        return existingGoogleProvider.user;
      }

      // 2. Try to find existing user by email
      const emailUser = await tx.user.findUnique({
        where: { email },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });

      if (emailUser) {
        await tx.authProvider.upsert({
          where: {
            userId_providerType: {
              userId: emailUser.id,
              providerType: 'google',
            },
          },
          update: {
            providerUserId: googleId,
          },
          create: {
            userId: emailUser.id,
            providerType: 'google',
            providerUserId: googleId,
          },
        });

        return emailUser;
      }

      // 3. Create new user and google auth_provider
      const baseUsername = (name || email.split('@')[0])
        .toLowerCase()
        .replace(/\s+/g, '_')
        .substring(0, 50);

      // Ensure username is unique
      let uniqueUsername = baseUsername;
      let counter = 1;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const existing = await tx.user.findUnique({
          where: { username: uniqueUsername },
          select: { id: true },
        });
        if (!existing) break;
        uniqueUsername = `${baseUsername}_${counter}`;
        counter += 1;
      }

      const newUser = await tx.user.create({
        data: {
          email,
          username: uniqueUsername,
          fullName: name || null,
          avatarUrl: picture || null,
          emailVerified: true,
        },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });

      await tx.authProvider.create({
        data: {
          userId: newUser.id,
          providerType: 'google',
          providerUserId: googleId,
        },
      });

      return newUser;
    });

    const token = generateJwt(user);

    res.json({
      message: 'Google login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
