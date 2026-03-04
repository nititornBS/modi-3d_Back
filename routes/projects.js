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

// Delete a Cloudinary image by its URL (no-op if not a Cloudinary URL or keys not set)
async function deleteCloudinaryByUrl(url) {
  if (!url || !url.includes('cloudinary.com') || !process.env.CLOUDINARY_API_SECRET) return;
  try {
    const match = url.match(/\/upload\/(?:v\d+\/)?(.+)\.\w+$/);
    if (match) await cloudinary.uploader.destroy(match[1]);
  } catch (err) {
    console.warn('[Projects] Cloudinary delete warning:', err.message);
  }
}

// POST /api/projects — save (create or update) a project
// Body: { id?, name, templateId?, bgUrl?, designsJson, thumbnail? }
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { id, name, templateId, bgUrl, designsJson, thumbnail } = req.body;

    if (!designsJson) {
      return res.status(400).json({ error: 'designsJson is required' });
    }

    await ensureUserExists(req.user);

    let project;
    if (id) {
      // Update existing — only if it belongs to this user
      const existing = await prisma.project.findFirst({
        where: { id, userId: req.user.userId },
      });
      if (!existing) return res.status(404).json({ error: 'Project not found' });

      // Delete old thumbnail if replaced
      if (thumbnail && existing.thumbnail && existing.thumbnail !== thumbnail) {
        await deleteCloudinaryByUrl(existing.thumbnail);
      }

      // Delete design images that are no longer present in the new save
      if (existing.designsJson && designsJson) {
        const oldData = JSON.parse(existing.designsJson);
        const newData = JSON.parse(designsJson);

        // Extract URLs from either 2D (array of {src,displaySrc}) or 3D ({images:[{url}]}) format
        const extractUrls = (data) => {
          if (Array.isArray(data)) {
            return new Set(data.flatMap(d => [d.src, d.displaySrc].filter(Boolean)));
          } else if (data?.images) {
            return new Set(data.images.map(img => img.url).filter(Boolean));
          }
          return new Set();
        };
        const newUrls = extractUrls(newData);

        if (Array.isArray(oldData)) {
          for (const d of oldData) {
            if (!newUrls.has(d.src)) await deleteCloudinaryByUrl(d.src);
            if (d.displaySrc && d.displaySrc !== d.src && !newUrls.has(d.displaySrc))
              await deleteCloudinaryByUrl(d.displaySrc);
          }
        } else if (oldData?.images) {
          for (const img of oldData.images) {
            if (!newUrls.has(img.url)) await deleteCloudinaryByUrl(img.url);
          }
        }
      }

      project = await prisma.project.update({
        where: { id },
        data:  { name: name || existing.name, templateId, bgUrl, designsJson, thumbnail },
      });
    } else {
      project = await prisma.project.create({
        data: {
          userId:      req.user.userId,
          name:        name || 'Untitled Project',
          templateId:  templateId || null,
          bgUrl:       bgUrl || null,
          designsJson,
          thumbnail:   thumbnail || null,
        },
      });
    }

    res.status(id ? 200 : 201).json({ project });
  } catch (error) {
    console.error('[Projects] Save error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/projects — list user's projects (summary, no designsJson)
router.get('/', authenticateToken, async (req, res) => {
  try {
    await ensureUserExists(req.user);
    const rows = await prisma.project.findMany({
      where:   { userId: req.user.userId },
      orderBy: { updatedAt: 'desc' },
      select:  { id: true, name: true, templateId: true, bgUrl: true, thumbnail: true, createdAt: true, updatedAt: true, designsJson: true },
    });
    const projects = rows.map(({ designsJson, ...p }) => {
      let projectType = '2d';
      try {
        const d = JSON.parse(designsJson);
        if (d && d.projectType === '3d') projectType = '3d';
      } catch {}
      return { ...p, projectType };
    });
    res.json({ projects });
  } catch (error) {
    console.error('[Projects] List error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/projects/:id — load full project (including designsJson)
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const project = await prisma.project.findFirst({
      where: { id: req.params.id, userId: req.user.userId },
    });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json({ project });
  } catch (error) {
    console.error('[Projects] Get error:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/projects/:id
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const project = await prisma.project.findFirst({
      where: { id: req.params.id, userId: req.user.userId },
    });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    // Delete thumbnail from Cloudinary
    await deleteCloudinaryByUrl(project.thumbnail);

    // Delete every design layer image from Cloudinary (handles both 2D and 3D formats)
    if (project.designsJson) {
      const data = JSON.parse(project.designsJson);
      if (Array.isArray(data)) {
        for (const d of data) {
          await deleteCloudinaryByUrl(d.src);
          if (d.displaySrc && d.displaySrc !== d.src) await deleteCloudinaryByUrl(d.displaySrc);
        }
      } else if (data?.images) {
        for (const img of data.images) {
          await deleteCloudinaryByUrl(img.url);
        }
      }
    }

    await prisma.project.delete({ where: { id: project.id } });
    res.json({ message: 'Deleted' });
  } catch (error) {
    console.error('[Projects] Delete error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
