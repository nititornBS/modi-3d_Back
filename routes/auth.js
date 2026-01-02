const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const { prisma } = require('../config/database');

const router = express.Router();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// JWT expiration times
const ACCESS_TOKEN_EXPIRY = '15m'; // Short-lived access token
const REFRESH_TOKEN_EXPIRY_DAYS = 7; // 7 days for refresh token

// Helper to generate JWT (access token)
const generateJwt = (user) =>
  jwt.sign(
    { userId: user.id, username: user.username, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );

// Helper to generate secure random refresh token
const generateRefreshToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Helper to hash refresh token (for storage)
const hashRefreshToken = async (token) => {
  return await bcrypt.hash(token, 10);
};

// Helper to create refresh token in database
const createRefreshToken = async (userId, refreshToken) => {
  const tokenHash = await hashRefreshToken(refreshToken);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);

  await prisma.refreshToken.create({
    data: {
      userId,
      tokenHash,
      expiresAt,
    },
  });

  return expiresAt;
};

// Check username availability (GET - query parameter)
router.get('/check-username', async (req, res) => {
  try {
    const { username } = req.query;

    // Validate input
    if (!username) {
      return res.status(400).json({ 
        available: false,
        error: 'Username is required' 
      });
    }

    // Trim and validate username format
    const trimmedUsername = username.trim();
    
    if (trimmedUsername.length < 3) {
      return res.status(400).json({ 
        available: false,
        error: 'Username must be at least 3 characters long' 
      });
    }

    if (trimmedUsername.length > 50) {
      return res.status(400).json({ 
        available: false,
        error: 'Username must be less than 50 characters' 
      });
    }

    // Check if username contains only allowed characters (alphanumeric, underscore, hyphen)
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(trimmedUsername)) {
      return res.status(400).json({ 
        available: false,
        error: 'Username can only contain letters, numbers, underscores, and hyphens' 
      });
    }

    // Check if username already exists
    const existingUser = await prisma.user.findUnique({
      where: { username: trimmedUsername },
      select: { id: true },
    });

    if (existingUser) {
      return res.json({ 
        available: false,
        message: 'Username is already taken' 
      });
    }

    // Username is available
    res.json({ 
      available: true,
      message: 'Username is available' 
    });
  } catch (error) {
    console.error('Check username error:', error);
    res.status(500).json({ 
      available: false,
      error: 'Internal server error' 
    });
  }
});

// Check username availability (POST - request body)
router.post('/check-username', async (req, res) => {
  try {
    const { username } = req.body;

    // Validate input
    if (!username) {
      return res.status(400).json({ 
        available: false,
        error: 'Username is required' 
      });
    }

    // Trim and validate username format
    const trimmedUsername = username.trim();
    
    if (trimmedUsername.length < 3) {
      return res.status(400).json({ 
        available: false,
        error: 'Username must be at least 3 characters long' 
      });
    }

    if (trimmedUsername.length > 50) {
      return res.status(400).json({ 
        available: false,
        error: 'Username must be less than 50 characters' 
      });
    }

    // Check if username contains only allowed characters (alphanumeric, underscore, hyphen)
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(trimmedUsername)) {
      return res.status(400).json({ 
        available: false,
        error: 'Username can only contain letters, numbers, underscores, and hyphens' 
      });
    }

    // Check if username already exists
    const existingUser = await prisma.user.findUnique({
      where: { username: trimmedUsername },
      select: { id: true },
    });

    if (existingUser) {
      return res.json({ 
        available: false,
        message: 'Username is already taken' 
      });
    }

    // Username is available
    res.json({ 
      available: true,
      message: 'Username is available' 
    });
  } catch (error) {
    console.error('Check username error:', error);
    res.status(500).json({ 
      available: false,
      error: 'Internal server error' 
    });
  }
});

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

    const refreshToken = generateRefreshToken();

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

      // Create refresh token
      const tokenHash = await hashRefreshToken(refreshToken);
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);

      await tx.refreshToken.create({
        data: {
          userId: user.id,
          tokenHash,
          expiresAt,
        },
      });

      return user;
    });

    const token = generateJwt(result);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      refreshToken,
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

    // Generate refresh token
    const refreshToken = generateRefreshToken();
    await createRefreshToken(user.id, refreshToken);

    const token = generateJwt(user);

    res.json({
      message: 'Login successful',
      token,
      refreshToken,
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

// Check JWT token status (expired or not)
router.post('/check-token', async (req, res) => {
  try {
    // Get token from Authorization header or request body
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    
    if (!token && req.body.token) {
      token = req.body.token;
    }

    if (!token) {
      return res.status(400).json({ 
        valid: false,
        error: 'Token is required. Provide it in Authorization header (Bearer token) or in request body as { "token": "..." }' 
      });
    }

    try {
      // Try to verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Token is valid
      const currentTime = Math.floor(Date.now() / 1000);
      const expiresAt = decoded.exp;
      const timeUntilExpiry = expiresAt - currentTime;

      res.json({
        valid: true,
        expired: false,
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        expiresIn: timeUntilExpiry, // seconds until expiry
        decoded: {
          userId: decoded.userId,
          username: decoded.username,
          email: decoded.email,
        },
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        // Token is expired
        const decoded = jwt.decode(token); // Decode without verification to get expiry info
        
        res.json({
          valid: false,
          expired: true,
          expiresAt: decoded?.exp ? new Date(decoded.exp * 1000).toISOString() : null,
          error: 'Token has expired',
        });
      } else if (error.name === 'JsonWebTokenError') {
        // Token is invalid (malformed, wrong secret, etc.)
        res.json({
          valid: false,
          expired: false,
          error: 'Invalid token',
        });
      } else {
        throw error; // Re-throw unexpected errors
      }
    }
  } catch (error) {
    console.error('Check token error:', error);
    res.status(500).json({ 
      valid: false,
      error: 'Internal server error' 
    });
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
    console.log('Google login request received');
    const { idToken } = req.body;

    if (!idToken) {
      console.log('Google login: Missing idToken');
      return res.status(400).json({ error: 'Google ID token is required' });
    }

    // Check if GOOGLE_CLIENT_ID is configured
    if (!process.env.GOOGLE_CLIENT_ID) {
      console.error('Google login: GOOGLE_CLIENT_ID not configured');
      return res.status(500).json({ error: 'Google OAuth not configured on server' });
    }

    // Verify the Google ID token
    let ticket;
    try {
      console.log('Google login: Verifying token...');
      ticket = await client.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      console.log('Google login: Token verified successfully');
    } catch (error) {
      console.error('Google token verification error:', error.message);
      return res.status(401).json({ 
        error: 'Invalid Google token',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
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
      // Extract name from Google payload (prefer full name, then given_name + family_name, then email)
      let displayName = name;
      if (!displayName) {
        const givenName = payload.given_name || '';
        const familyName = payload.family_name || '';
        displayName = `${givenName} ${familyName}`.trim();
      }
      
      // Generate username from Google name (or email if no name)
      let baseUsername = displayName || email.split('@')[0];
      
      // Clean username: lowercase, replace spaces with underscores, remove invalid characters
      baseUsername = baseUsername
        .toLowerCase()
        .replace(/\s+/g, '_')           // Replace spaces with underscores
        .replace(/[^a-z0-9_-]/g, '')    // Remove invalid characters (keep only letters, numbers, _, -)
        .replace(/_{2,}/g, '_')         // Replace multiple underscores with single
        .replace(/^-+|-+$/g, '')        // Remove leading/trailing hyphens
        .substring(0, 50);              // Limit to 50 characters
      
      // Ensure minimum length (if too short, use email prefix)
      if (baseUsername.length < 3) {
        baseUsername = email.split('@')[0].toLowerCase().substring(0, 50);
      }

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
        // Append counter to make it unique (e.g., john_doe_1, john_doe_2)
        uniqueUsername = `${baseUsername}_${counter}`;
        // Prevent infinite loop (max 1000 attempts)
        if (counter > 1000) {
          // Fallback: use email prefix with timestamp
          uniqueUsername = `${email.split('@')[0]}_${Date.now()}`.substring(0, 50);
          break;
        }
        counter += 1;
      }

      const newUser = await tx.user.create({
        data: {
          email,
          username: uniqueUsername,
          fullName: displayName || name || null,
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

    // Generate refresh token
    const refreshToken = generateRefreshToken();
    await createRefreshToken(user.id, refreshToken);

    const token = generateJwt(user);

    console.log('Google login: Success for user', user.email);
    
    // Ensure Content-Type is set
    res.setHeader('Content-Type', 'application/json');
    
    res.status(200).json({
      message: 'Google login successful',
      token,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Google login error:', error);
    console.error('Error stack:', error.stack);
    
    // Ensure we always return valid JSON
    if (!res.headersSent) {
      res.setHeader('Content-Type', 'application/json');
      res.status(500).json({ 
        error: 'Internal server error',
        message: error.message || 'An error occurred during Google login',
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
      });
    } else {
      // If headers already sent, log the error
      console.error('Headers already sent, cannot send error response');
    }
  }
});

// Refresh token endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    // Find all refresh tokens for this user (we need to check each one)
    // Get all non-revoked, non-expired refresh tokens
    const allRefreshTokens = await prisma.refreshToken.findMany({
      where: {
        revoked: false,
        expiresAt: {
          gt: new Date(),
        },
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

    // Check each token hash against the provided refresh token
    let validToken = null;
    for (const tokenRecord of allRefreshTokens) {
      const isValid = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
      if (isValid) {
        validToken = tokenRecord;
        break;
      }
    }

    if (!validToken) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    // Revoke the old refresh token
    await prisma.refreshToken.update({
      where: { id: validToken.id },
      data: { revoked: true },
    });

    // Generate new access token and refresh token
    const newRefreshToken = generateRefreshToken();
    await createRefreshToken(validToken.user.id, newRefreshToken);

    const newAccessToken = generateJwt(validToken.user);

    res.json({
      message: 'Token refreshed successfully',
      token: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint (revoke refresh token)
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    // Find and revoke the refresh token
    const allRefreshTokens = await prisma.refreshToken.findMany({
      where: {
        revoked: false,
      },
    });

    for (const tokenRecord of allRefreshTokens) {
      const isValid = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
      if (isValid) {
        await prisma.refreshToken.update({
          where: { id: tokenRecord.id },
          data: { revoked: true },
        });
        return res.json({ message: 'Logged out successfully' });
      }
    }

    // Token not found or already revoked
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
