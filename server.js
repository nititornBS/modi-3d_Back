const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { initDatabase } = require('./config/database');
const authRoutes = require('./routes/auth');
const { authenticateToken } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, or same-origin)
    if (!origin) return callback(null, true);
    
    // List of exact allowed origins for local development
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://localhost:5174',
      process.env.FRONTEND_URL, // Additional frontend URL from env
    ].filter(Boolean); // Remove undefined values
    
    // Allow any origin that contains modi-3d.vercel.app
    // This includes the main domain (https://modi-3d.vercel.app) 
    // and any preview deployments (e.g., https://modi-3d-git-main-username.vercel.app)
    if (origin.includes('modi-3d.vercel.app')) {
      return callback(null, true);
    }
    
    // Allow localhost in development
    if (process.env.NODE_ENV === 'development' || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // Reject all other origins in production
    console.log('CORS blocked origin:', origin);
    callback(new Error(`Origin ${origin} not allowed by CORS`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Authorization'],
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Request logging middleware (for debugging)
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// Ensure all responses are JSON
app.use((req, res, next) => {
  // Set default Content-Type to JSON
  res.setHeader('Content-Type', 'application/json');
  next();
});

// Initialize database
initDatabase()
  .then(() => {
    console.log('Database initialized');
  })
  .catch((error) => {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  });

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Modi 3D Backend API is running' });
});

// Authentication routes
app.use('/api/auth', authRoutes);

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ 
    message: 'This is a protected route',
    user: req.user 
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  console.error('Error stack:', err.stack);
  
  // Handle CORS errors specifically
  if (err.message && err.message.includes('CORS')) {
    if (!res.headersSent) {
      return res.status(403).json({ 
        error: 'CORS policy violation',
        message: err.message
      });
    }
  }
  
  // Ensure response is always JSON
  if (!res.headersSent) {
    res.setHeader('Content-Type', 'application/json');
    res.status(err.status || 500).json({ 
      error: err.message || 'Something went wrong!',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
