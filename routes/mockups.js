const express    = require('express');
const cloudinary = require('cloudinary').v2;
const { prisma } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

cloudinary.config({
  cloud_name:  process.env.CLOUDINARY_CLOUD_NAME,
  api_key:     process.env.CLOUDINARY_API_KEY,
  api_secret:  process.env.CLOUDINARY_API_SECRET,
});

// Auto-create user row in local SQLite from JWT data (first use after DB switch)
async function ensureUserExists(jwtUser) {
  await prisma.user.upsert({
    where:  { id: jwtUser.userId },
    update: {},
    create: {
      id:       jwtUser.userId,
      email:    jwtUser.email,
      username: jwtUser.username || null,
    },
  });
}

// POST /api/mockups/save
// Frontend uploads directly to Cloudinary, then sends the result here.
// Body: { url, publicId, name, category }
router.post('/save', authenticateToken, async (req, res) => {
  try {
    const { url, publicId, name, category } = req.body;

    console.log('[Save] Received from frontend:', { url, publicId, name, category });
    console.log('[Save] User from JWT:', req.user.userId, req.user.email);

    if (!url || !publicId) {
      return res.status(400).json({ error: 'url and publicId are required' });
    }

    await ensureUserExists(req.user);

    const background = await prisma.userBackground.create({
      data: {
        userId:   req.user.userId,
        name:     name || publicId,
        filename: publicId,
        mimetype: 'image/*',
        size:     0,
        url,
        category: category || 'custom',
      },
    });

    console.log('[Save] Saved to DB with id:', background.id);
    res.status(201).json({ background });
  } catch (error) {
    console.error('[Save] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/mockups — list user's saved backgrounds
router.get('/', authenticateToken, async (req, res) => {
  try {
    await ensureUserExists(req.user);
    const backgrounds = await prisma.userBackground.findMany({
      where:   { userId: req.user.userId },
      orderBy: { createdAt: 'desc' },
    });
    res.json({ backgrounds });
  } catch (error) {
    console.error('Get mockups error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/mockups/:id — delete from DB and from Cloudinary
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    await ensureUserExists(req.user);
    const bg = await prisma.userBackground.findFirst({
      where: { id: req.params.id, userId: req.user.userId },
    });
    if (!bg) return res.status(404).json({ error: 'Not found' });

    // Remove from Cloudinary (only if keys are configured)
    if (bg.filename && process.env.CLOUDINARY_API_SECRET) {
      try {
        await cloudinary.uploader.destroy(bg.filename);
      } catch (err) {
        console.warn('Cloudinary delete warning:', err.message);
      }
    }

    await prisma.userBackground.delete({ where: { id: bg.id } });
    res.json({ message: 'Deleted' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
