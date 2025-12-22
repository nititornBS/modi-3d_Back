const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

// Prisma client (uses DATABASE_URL from .env)
const prisma = new PrismaClient();

// Initialize database (simple connection test)
const initDatabase = async () => {
  try {
    await prisma.$connect();
    console.log('Connected to PostgreSQL via Prisma');
  } catch (error) {
    console.error('Error connecting to database via Prisma:', error);
    throw error;
  }
};

module.exports = {
  prisma,
  initDatabase,
};
