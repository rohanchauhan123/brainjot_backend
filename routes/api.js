const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');
const Project = require('../models/Project');
const Space = require('../models/Space');
const User = require('../models/User');
const Feedback = require('../models/Feedback');
const Notification = require('../models/Notification');
const Otp = require('../models/Otp');
const Invitation = require('../models/Invitation');
const { UPLOADS_DIR, useR2, getPresignedPutUrl, deleteStoredFile, deleteUserFiles, filePublicUrl } = require('../utils/storage');
const { livekitEnabled, activeCalls, generateToken, LIVEKIT_URL } = require('../utils/livekit');
const logger = require('../utils/logger');

const router = express.Router();

function emitProjectUpdate(req, projectId) {
  req.app.get('io')?.to(`project:${projectId}`).emit('project_updated', { projectId });
}

const VALID_COLLAB_ROLES = ['editor', 'viewer'];
const HEX_COLOR_RE = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
function isValidColor(c) { return typeof c === 'string' && HEX_COLOR_RE.test(c); }
function safeIcon(icon, fallback = '📁') { return typeof icon === 'string' ? [...icon].slice(0, 4).join('') || fallback : fallback; }
const APP_URL = process.env.APP_URL || 'https://brainjotapp.up.railway.app';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const FROM_EMAIL = process.env.FROM_EMAIL || 'BrainJot <onboarding@resend.dev>';
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendInviteEmail({ to, toName, inviterName, projectTitle, spaceTitle, inviteToken }) {
  if (!resend) {
    logger.warn({ to }, '[email] RESEND_API_KEY not configured — skipping invite');
    return;
  }
  const subjectTarget = projectTitle ? `project "${projectTitle}"` : `space "${spaceTitle}"`;
  const displayTarget = projectTitle || spaceTitle;
  const joinUrl = inviteToken ? `${APP_URL}/?join=${inviteToken}` : APP_URL;
  try {
    const result = await resend.emails.send({
      from: FROM_EMAIL,
      to,
      subject: `${inviterName} invited you to collaborate on BrainJot`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#0a0a0a;color:#f5f5f5;border-radius:16px">
          <h1 style="font-size:28px;font-weight:800;margin:0 0 8px">🧠 BrainJot</h1>
          <p style="color:#888;font-size:14px;margin:0 0 32px">Your brain at a glance</p>

          <p style="font-size:16px;line-height:1.6;margin:0 0 24px">
            Hey${toName ? ` ${toName}` : ''},<br><br>
            <strong>${inviterName}</strong> has invited you to collaborate on the ${subjectTarget}.
          </p>

          <a href="${joinUrl}" style="display:inline-block;background:#7C6FCD;color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px;font-weight:700;font-size:15px">
            Open ${displayTarget} in BrainJot →
          </a>

          <p style="font-size:13px;color:#666;margin:32px 0 0;line-height:1.6">
            Click the link above to access the workspace. If you do not have an account yet, you can sign up for free and you will be added to the collaboration automatically.
          </p>
        </div>
      `,
    });
    logger.info({ to, messageId: result?.id }, '[email] invite_sent');
  } catch (err) {
    logger.error({ to, message: err.message, status: err.statusCode }, '[email] invite_failed');
    // Hook point: Sentry.captureException(err, { extra: { to } });
  }
}

const SALT_ROUNDS = 12;

// ── Multer setup ──────────────────────────────────────────────────
const ALLOWED_EXT = new Set([
  'jpg','jpeg','png','gif','webp','pdf',
  'doc','docx','xls','xlsx','ppt','pptx',
  'mp4','mov','zip','txt','csv',
]);

// Allowed MIME types for general uploads (maps extension category → allowed MIME prefixes)
const ALLOWED_MIME_PREFIXES = new Set([
  'image/', 'video/', 'application/pdf',
  'application/msword', 'application/vnd.openxmlformats',
  'application/vnd.ms-', 'application/zip', 'text/',
]);

function makeKey(taskId, projectId, ext) {
  const prefix = taskId ? `task_${taskId}_` : `${projectId}_`;
  return `${prefix}${crypto.randomUUID()}.${ext}`;
}

// Always save to disk first. If R2 is configured, the handler manually pushes
// the file to R2 after multer writes it locally and then deletes the temp copy.
// This avoids multerS3 streaming directly to R2, which caused SSL handshake
// failures in containerised environments.
const diskStorage = multer.diskStorage({
  destination(_req, _file, cb) {
    if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    cb(null, UPLOADS_DIR);
  },
  filename(_req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    cb(null, `tmp_${crypto.randomUUID()}.${ext}`);
  },
});

const upload = multer({
  storage: diskStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    const mimeOk = [...ALLOWED_MIME_PREFIXES].some(p => file.mimetype.startsWith(p));
    if (ALLOWED_EXT.has(ext) && mimeOk) cb(null, true);
    else cb(new Error('File type not allowed'));
  },
});

const avatarDiskStorage = multer.diskStorage({
  destination(_req, _file, cb) {
    const dir = path.join(UPLOADS_DIR, 'avatars');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, _file, cb) => cb(null, `${req.session.userId}.jpg`),
});
const ALLOWED_AVATAR_EXT = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif']);
const ALLOWED_AVATAR_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const uploadAvatar = multer({
  storage: avatarDiskStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    if (ALLOWED_AVATAR_EXT.has(ext) && ALLOWED_AVATAR_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Avatar must be a JPG, PNG, WebP, or GIF image'));
  },
});

function conditionalUpload(req, res, next) {
  const action = req.query.action;
  // In R2 mode, file uploads are browser-direct via presigned URLs — no server-side
  // multipart handling needed. Skip multer entirely and let the route handlers respond.
  if (useR2 && (action === 'upload' || action === 'upload_task_file' || action === 'upload_avatar')) {
    return next();
  }
  if (action === 'upload' || action === 'upload_task_file') {
    upload.single('file')(req, res, (err) => {
      if (!err) return next();
      const multer = require('multer');
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 50MB)' });
        return res.status(400).json({ error: err.message });
      }
      res.status(400).json({ error: err.message || 'Upload failed' });
    });
  } else if (action === 'upload_avatar') {
    uploadAvatar.single('file')(req, res, (err) => {
      if (!err) return next();
      const multer = require('multer');
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Avatar too large (max 2MB)' });
        return res.status(400).json({ error: err.message });
      }
      res.status(400).json({ error: err.message || 'Upload failed' });
    });
  } else {
    next();
  }
}

// ── Helpers ───────────────────────────────────────────────────────
function uid() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 13);
}

function now() {
  return new Date().toISOString().slice(0, 16).replace('T', ' ');
}

function toPlain(docs) {
  return docs.map(doc => {
    const obj = doc.toObject ? doc.toObject() : doc;
    const { _id, __v, ...rest } = obj;
    return rest;
  });
}

function cloneTaskForDuplicate(task) {
  const { _id, id, ...rest } = task.toObject ? task.toObject() : task;
  return { ...rest, id: 'task_' + uid(), files: [] };
}

// ── Seed default data per user ────────────────────────────────────
async function seedDefaultData(userId) {
  const spaceCount = await Space.countDocuments({ ownerId: userId });
  let defaultSpaceId;

  if (spaceCount === 0) {
    const workId = 'space_' + uid();
    const personalId = 'space_' + uid();
    await Space.create({ id: workId,     title: 'Work',     icon: '💼', color: '#3b82f6', description: 'Professional projects',   ownerId: userId, __orderRank: 0 });
    await Space.create({ id: personalId, title: 'Personal', icon: '🏠', color: '#10b981', description: 'Personal goals & projects', ownerId: userId, __orderRank: 1 });
    defaultSpaceId = workId;
  } else {
    const first = await Space.findOne({ ownerId: userId }).sort({ __orderRank: 1 });
    defaultSpaceId = first.id;
  }

  const projectCount = await Project.countDocuments({ ownerId: userId });
  if (projectCount > 0) return;

  const defaults = [
    {
      id: 'proj_' + uid(), title: 'My First Project', subtitle: 'Get started with BrainJot',
      color: '#7C6FCD', tag: 'Project',
      tasks: [
        { id: 'task_' + uid(), text: 'Create your first task', badge: 'Getting Started' },
        { id: 'task_' + uid(), text: 'Add a deadline to a task', badge: 'Getting Started' },
        { id: 'task_' + uid(), text: 'Explore Spaces in the sidebar', badge: 'Getting Started' },
      ],
    },
  ];

  for (let i = 0; i < defaults.length; i++) {
    const d = defaults[i];
    await Project.create({
      ...d,
      spaceId: defaultSpaceId,
      ownerId: userId,
      notes: '',
      richNotes: '',
      files: [],
      collaborators: [],
      __orderRank: i,
      tasks: d.tasks.map(t => ({
        ...t,
        done: false,
        notes: '',
        richNotes: '',
        files: [],
        deadline: '',
        assignee: '',
        priority: '',
      })),
    });
  }
}

// ── Rate limiters ─────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ ip: req.ip, action: req.query.action }, '[rate_limit] auth limiter triggered');
    res.status(429).json({ error: 'Too many attempts, please try again later' });
  },
});

// Per-user rate limit for all authenticated API actions
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  keyGenerator: (req) => req.session?.userId || req.ip,
  validate: { ip: false },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ ip: req.ip, userId: req.session?.userId, action: req.query.action }, '[rate_limit] api limiter triggered');
    res.status(429).json({ error: 'Too many requests, please slow down' });
  },
});

// Strict rate limit for data export (5 per hour per user)
const exportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.session?.userId || req.ip,
  validate: { ip: false },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ ip: req.ip, userId: req.session?.userId }, '[rate_limit] export limiter triggered');
    res.status(429).json({ error: 'Export limit reached, please try again later' });
  },
});

// ── Auth middleware ───────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Download helper ───────────────────────────────────────────────
router.get('/download', requireAuth, (req, res) => {
  const fileUrl = req.query.url;
  const originalName = req.query.name;

  if (!fileUrl) return res.status(400).send('File URL is required');

  // R2 files have a full HTTPS public URL — only redirect to our own R2 bucket domain
  if (fileUrl.startsWith('https://')) {
    const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || '';
    if (!R2_PUBLIC_URL || !fileUrl.startsWith(R2_PUBLIC_URL + '/')) {
      return res.status(400).send('Invalid file URL');
    }
    return res.redirect(fileUrl);
  }

  // Local dev: serve from disk
  const filename = path.basename(fileUrl);
  const filePath = path.join(UPLOADS_DIR, filename);
  if (!filePath.startsWith(UPLOADS_DIR + path.sep)) {
    return res.status(400).send('Invalid file path');
  }
  if (fs.existsSync(filePath)) {
    res.download(filePath, originalName || filename);
  } else {
    res.status(404).send('File not found');
  }
});

router.use(conditionalUpload);

// ── GET routes ────────────────────────────────────────────────────
router.get('/', apiLimiter, async (req, res) => {
  const action = req.query.action;

  if (action === 'check_username') {
    const raw = (req.query.username || '').toLowerCase().trim();
    if (!raw || raw.length < 3) { res.json({ available: false, error: 'Username must be at least 3 characters' }); return; }
    if (raw.length > 20) { res.json({ available: false, error: 'Username must be 20 characters or less' }); return; }
    if (!/^[a-z0-9_]+$/.test(raw)) { res.json({ available: false, error: 'Only letters, numbers and underscores allowed' }); return; }
    const exists = await User.findOne({ username: raw });
    res.json({ available: !exists });
    return;
  }

  if (action === 'check') {
    if (req.session.userId) {
      const user = await User.findOne({ id: req.session.userId }).select('name email username role avatarUrl -_id');
      if (user) req.session.userRole = user.role || 'user';
      res.json({ loggedIn: true, user: user ? { id: req.session.userId, name: user.name, email: user.email, username: user.username || '', role: user.role || 'user', avatarUrl: user.avatarUrl || '' } : null, features: { livekit: livekitEnabled } });
    } else {
      res.json({ loggedIn: false });
    }
    return;
  }

  if (!req.session.userId) { res.status(401).json({ error: 'Unauthorized' }); return; }
  const userId = req.session.userId;

  if (action === 'find_user') {
    const q = (req.query.q || '').replace(/^@/, '').toLowerCase().trim();
    if (q.length < 2) { res.json({ users: [] }); return; }
    const safeQ = q.replace(/[^a-z0-9_]/g, '');
    const users = await User.find({ username: { $regex: '^' + safeQ }, id: { $ne: userId } })
      .select('id name username avatarUrl -_id').limit(8).lean();
    res.json({ users });
    return;
  }

  if (action === 'get_notifications') {
    const notifs = await Notification.find({ toUserId: userId })
      .sort({ createdAt: -1 }).limit(50).lean();
    res.json({ notifications: notifs.map(({ _id, __v, ...n }) => n) });
    return;
  }

  if (action === 'get') {
    // Keep session role in sync with DB so revocations take effect within one poll cycle
    const freshUser = await User.findOne({ id: userId }).select('role -_id').lean();
    if (freshUser) req.session.userRole = freshUser.role || 'user';
    const spaces   = await Space.find({ ownerId: userId }).sort({ __orderRank: 1 }).select('-_id -__v');
    const projects = await Project.find({ ownerId: userId }).sort({ __orderRank: 1 }).select('-_id -__v');
    // Also fetch projects in owned spaces that were created by space collaborators
    const ownedSpaceIds = toPlain(spaces).map(s => s.id).filter(Boolean);
    const spaceEditorProjectDocs = ownedSpaceIds.length
      ? await Project.find({ spaceId: { $in: ownedSpaceIds }, ownerId: { $ne: userId } }).select('-_id -__v').lean()
      : [];
    const sharedProjectDocs = await Project.find({ 'collaborators.userId': userId, ownerId: { $ne: userId } }).select('-_id -__v').lean();
    const sharedSpaceDocs   = await Space.find({ 'collaborators.userId': userId, ownerId: { $ne: userId } }).select('-_id -__v').lean();
    // Fetch projects belonging to shared spaces so the SpaceView can render them
    const sharedSpaceIds = sharedSpaceDocs.map(s => s.id).filter(Boolean);
    const sharedSpaceProjectDocs = sharedSpaceIds.length
      ? await Project.find({ spaceId: { $in: sharedSpaceIds } }).select('-_id -__v').lean()
      : [];
    // Look up owner info so collaborators can @mention the owner in comments
    const allOwnerIds = [...new Set([...sharedProjectDocs.map(p => p.ownerId), ...sharedSpaceDocs.map(s => s.ownerId)])].filter(Boolean);
    const ownerUsers = allOwnerIds.length ? await User.find({ id: { $in: allOwnerIds } }).select('id name username avatarUrl -_id').lean() : [];
    const ownerMap = Object.fromEntries(ownerUsers.map(u => [u.id, u]));
    const annotateShared = (items) => items.map(item => {
      const me = (item.collaborators || []).find(c => c.userId === userId);
      const ownerUser = ownerMap[item.ownerId];
      const ownerInfo = ownerUser ? { userId: item.ownerId, name: ownerUser.name, username: ownerUser.username || '', avatarUrl: ownerUser.avatarUrl || '' } : null;
      return { ...item, myRole: me?.role || 'viewer', ownerInfo };
    });
    res.json({
      spaces: toPlain(spaces),
      // Merge collaborator-created projects in owned spaces so they appear in the space view
      projects: [...toPlain(projects), ...spaceEditorProjectDocs],
      sharedProjects: annotateShared(sharedProjectDocs),
      sharedSpaces: annotateShared(sharedSpaceDocs).map(s => ({
        ...s,
        projects: sharedSpaceProjectDocs.filter(p => p.spaceId === s.id),
      })),
    });
    return;
  }

  if (action === 'get_feedback') {
    const isAdmin = req.session.userRole === 'superadmin';
    const raw = await Feedback.find({}).sort({ createdAt: -1 }).limit(200).lean();
    res.json({
      items: raw.map(({ _id, __v, upvotes, userId: feedbackUserId, ...rest }) => ({
        ...rest,
        ...(isAdmin ? { userId: feedbackUserId } : {}),
        upvoteCount: upvotes.length,
        hasUpvoted: upvotes.includes(userId),
      })),
    });
    return;
  }

  if (action === 'get_task_comments') {
    const { projectId, taskId } = req.query;
    if (!projectId || !taskId) { res.status(400).json({ error: 'Missing data' }); return; }
    const proj = await Project.findOne({
      id: projectId,
      $or: [{ ownerId: userId }, { 'collaborators.userId': userId }],
    }).select('tasks -_id').lean();
    if (!proj) { res.status(404).json({ error: 'Not found' }); return; }
    const taskDoc = (proj.tasks || []).find(t => t.id === taskId);
    res.json({ comments: taskDoc?.comments || [] });
    return;
  }

  // ── get_upload_url ──────────────────────────────────────────────
  // Returns a presigned PUT URL so the browser uploads directly to R2.
  // In disk mode, returns { diskMode: true } — frontend falls back to multipart.
  if (action === 'get_upload_url') {
    if (!useR2) { res.json({ ok: true, diskMode: true }); return; }

    const { filename, mimeType, size, type, projectId, taskId } = req.query;
    if (!filename || !type) { res.status(400).json({ error: 'filename and type required' }); return; }

    const ext = path.extname(filename).toLowerCase().replace('.', '');
    const maxBytes = type === 'avatar' ? 2 * 1024 * 1024 : 50 * 1024 * 1024;
    if (size && Number(size) > maxBytes) {
      return res.status(400).json({ error: type === 'avatar' ? 'Avatar too large (max 2MB)' : 'File too large (max 50MB)' });
    }

    if (type === 'avatar') {
      if (!['jpg', 'jpeg', 'png', 'webp', 'gif'].includes(ext)) {
        return res.status(400).json({ error: 'Avatar must be jpg/png/webp/gif' });
      }
    } else {
      if (!ALLOWED_EXT.has(ext)) return res.status(400).json({ error: 'File type not allowed' });
    }

    let key;
    if (type === 'avatar') {
      key = `avatars/${userId}.jpg`;
    } else if (type === 'task') {
      if (!projectId || !taskId) return res.status(400).json({ error: 'projectId and taskId required' });
      key = makeKey(taskId, projectId, ext);
    } else {
      if (!projectId) return res.status(400).json({ error: 'projectId required' });
      key = makeKey(null, projectId, ext);
    }

    const fileId = uid();
    const uploadUrl = await getPresignedPutUrl(key, mimeType || 'application/octet-stream');
    logger.info({ userId, type, key, fileId }, '[upload] presigned URL issued');
    res.json({ ok: true, uploadUrl, fileKey: key, fileId });
    return;
  }

  // ── get_call_token ── (GET because it's called from frontend as GET)
  if (action === 'get_call_token') {
    if (!livekitEnabled) { res.status(400).json({ error: 'Calling is not configured on this server' }); return; }
    const { projectId, spaceId, callType = 'audio' } = req.query;
    if (!projectId && !spaceId) { res.status(400).json({ error: 'projectId or spaceId required' }); return; }
    if (!['audio', 'video'].includes(callType)) { res.status(400).json({ error: 'Invalid callType' }); return; }

    const callId = projectId || spaceId;
    const entityType = projectId ? 'project' : 'space';

    if (projectId) {
      const project = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId } } }] });
      if (!project) { res.status(404).json({ error: 'Project not found or access denied' }); return; }
    } else {
      const space = await Space.findOne({ id: spaceId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId } } }] });
      if (!space) { res.status(404).json({ error: 'Space not found or access denied' }); return; }
    }

    const user = await User.findOne({ id: userId }).select('name');
    const userName = user?.name || 'Host';
    const roomName = `call_${entityType}_${callId}`;
    const socketRoom = `${entityType}:${callId}`;

    if (!activeCalls.has(callId)) {
      activeCalls.set(callId, { hostUserId: userId, hostName: userName, callType, roomName, entityType, startedAt: Date.now() });
      req.app.get('io')?.to(socketRoom).emit('call:started', { callId, entityType, hostUserId: userId, hostName: userName, callType });
      logger.info({ callId, entityType, userId, callType }, '[call] started');
    }

    const token = await generateToken(userId, userName, roomName);
    res.json({ ok: true, token, roomName, livekitUrl: LIVEKIT_URL });
    return;
  }

  res.status(404).json({ error: 'Unknown action' });
});

// ── POST routes ───────────────────────────────────────────────────
router.post('/', apiLimiter, async (req, res, next) => {
  const action = req.query.action;

  // ── send_otp ──
  if (action === 'send_otp') {
    return authLimiter(req, res, async () => {
      try {
        const { email } = req.body;
        if (!email?.trim()) { return res.status(400).json({ error: 'Email is required' }); }
        const cleanEmail = email.toLowerCase().trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) { return res.status(400).json({ error: 'Invalid email address' }); }

        if (!resend) {
          logger.warn({ to: cleanEmail }, '[otp] RESEND_API_KEY not configured — mock OTP sending');
          // For testing without resend key, we can log it
          const otp = '123456';
          await Otp.deleteOne({ email: cleanEmail });
          await Otp.create({ email: cleanEmail, otp });
          logger.info({ email: cleanEmail, otp }, '[otp] generated');
          return res.json({ ok: true, message: 'OTP sent successfully (Dev mode: 123456)' });
        }

        const otp = Math.floor(100000 + Math.random() * 90000).toString(); // 6-digit OTP
        await Otp.deleteOne({ email: cleanEmail });
        await Otp.create({ email: cleanEmail, otp });

        await resend.emails.send({
          from: FROM_EMAIL,
          to: cleanEmail,
          subject: 'Your BrainJot Verification OTP',
          html: `
            <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#0a0a0a;color:#f5f5f5;border-radius:16px">
              <h1 style="font-size:28px;font-weight:800;margin:0 0 8px">🧠 BrainJot</h1>
              <p style="color:#888;font-size:14px;margin:0 0 32px">Your verification code</p>
              <p style="font-size:16px;line-height:1.6;margin:0 0 24px">Here is your 6-digit OTP code to verify your email:</p>
              <div style="background:#1a1a1a;border:1px solid #333;font-size:32px;font-weight:800;letter-spacing:6px;text-align:center;padding:16px;border-radius:12px;color:#7C6FCD;margin-bottom:24px">${otp}</div>
              <p style="font-size:13px;color:#666;line-height:1.6">This OTP code is valid for 5 minutes.</p>
            </div>
          `
        });
        logger.info({ email: cleanEmail }, '[otp] sent');
        res.json({ ok: true, message: 'OTP sent successfully' });
      } catch (err) {
        next(err);
      }
    });
  }

  // ── verify_otp ──
  if (action === 'verify_otp') {
    return authLimiter(req, res, async () => {
      try {
        const { email, otp, name, username } = req.body;
        if (!email?.trim() || !otp?.trim()) {
          return res.status(400).json({ error: 'Email and OTP are required' });
        }
        const cleanEmail = email.toLowerCase().trim();
        const record = await Otp.findOne({ email: cleanEmail, otp: otp.trim() });
        if (!record) {
          return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Delete used OTP
        await Otp.deleteOne({ _id: record._id });

        const user = await User.findOne({ email: cleanEmail });
        if (user) {
          // Auto-elevate if email is in ADMIN_EMAILS
          if (ADMIN_EMAILS.includes(user.email) && user.role !== 'superadmin') {
            await User.updateOne({ id: user.id }, { role: 'superadmin' });
            user.role = 'superadmin';
          }
          await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
          req.session.userId = user.id;
          req.session.userRole = user.role || 'user';
          logger.info({ userId: user.id, ip: req.ip, role: user.role }, '[auth] otp_login_success');
          return res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, username: user.username || '', role: user.role || 'user', avatarUrl: user.avatarUrl || '' } });
        } else {
          // If registration params are provided, complete signup
          if (name?.trim() && username?.trim()) {
            const cleanUsername = username.toLowerCase().trim();
            if (cleanUsername.length < 3 || cleanUsername.length > 20 || !/^[a-z0-9_]+$/.test(cleanUsername)) {
              return res.status(400).json({ error: 'Username must be 3-20 chars, letters/numbers/underscores only' });
            }
            const takenUsername = await User.findOne({ username: cleanUsername });
            if (takenUsername) {
              return res.status(409).json({ error: 'Username already taken' });
            }
            const userId = 'user_' + uid();
            const role = ADMIN_EMAILS.includes(cleanEmail) ? 'superadmin' : 'user';
            const passwordHash = await bcrypt.hash(crypto.randomUUID(), SALT_ROUNDS); // Google/OTP passwordless user
            const newUser = await User.create({ id: userId, email: cleanEmail, name: name.trim(), username: cleanUsername, passwordHash, role });
            await seedDefaultData(userId);
            await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
            req.session.userId = userId;
            req.session.userRole = role;
            logger.info({ userId, ip: req.ip, role }, '[auth] otp_register_success');
            return res.json({ ok: true, user: { id: userId, name: newUser.name, email: newUser.email, username: newUser.username, role, avatarUrl: '' } });
          }
          // Request registration details from frontend
          return res.json({ ok: true, requiresRegistration: true });
        }
      } catch (err) {
        next(err);
      }
    });
  }

  // ── google_auth ──
  if (action === 'google_auth') {
    return authLimiter(req, res, async () => {
      try {
        const { credential } = req.body;
        if (!credential || typeof credential !== 'string') {
          return res.status(400).json({ error: 'Credential token is required' });
        }

        // Decode the Google ID token (JWT) without a library.
        // We decode the payload segment (index 1) which is base64url-encoded JSON.
        // Full signature verification is done via Google's tokeninfo endpoint.
        let payload;
        try {
          const parts = credential.split('.');
          if (parts.length !== 3) throw new Error('Malformed JWT');
          const base64Payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
          const jsonStr = Buffer.from(base64Payload, 'base64').toString('utf8');
          payload = JSON.parse(jsonStr);
        } catch (decodeErr) {
          logger.warn({ decodeErr: decodeErr.message }, '[auth] google token decode failed');
          return res.status(401).json({ error: 'Invalid Google token format' });
        }

        // Validate expected fields exist
        const email = (payload.email || '').toLowerCase().trim();
        if (!email) {
          return res.status(400).json({ error: 'Email not found in Google token' });
        }
        if (!payload.email_verified) {
          return res.status(401).json({ error: 'Google email is not verified' });
        }

        // Validate audience (client_id) if configured
        if (process.env.GOOGLE_CLIENT_ID) {
          const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
          if (!tokenAud.includes(process.env.GOOGLE_CLIENT_ID)) {
            logger.warn({ tokenAud, expected: process.env.GOOGLE_CLIENT_ID }, '[auth] google_auth audience mismatch');
            return res.status(401).json({ error: 'Google token was not issued for this app' });
          }
        }

        // Validate token expiry
        if (payload.exp && Date.now() / 1000 > payload.exp) {
          return res.status(401).json({ error: 'Google token has expired — please sign in again' });
        }

        let user = await User.findOne({ email });
        if (!user) {
          // Auto-generate username from email
          let baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 15);
          if (baseUsername.length < 3) baseUsername = 'user';
          let cleanUsername = baseUsername;
          let count = 0;
          while (await User.findOne({ username: cleanUsername })) {
            count++;
            cleanUsername = `${baseUsername}${count}`;
          }

          const userId = 'user_' + uid();
          const role = ADMIN_EMAILS.includes(email) ? 'superadmin' : 'user';
          const passwordHash = await bcrypt.hash(crypto.randomUUID(), SALT_ROUNDS);
          const avatarUrl = payload.picture || '';

          user = await User.create({
            id: userId,
            email,
            name: payload.name || email.split('@')[0],
            username: cleanUsername,
            passwordHash,
            role,
            avatarUrl
          });
          await seedDefaultData(userId);
          logger.info({ userId, ip: req.ip, role }, '[auth] google_register_success');
        } else {
          // Auto-elevate if email is in ADMIN_EMAILS
          if (ADMIN_EMAILS.includes(user.email) && user.role !== 'superadmin') {
            await User.updateOne({ id: user.id }, { role: 'superadmin' });
            user.role = 'superadmin';
          }
          // Update profile pic if not set
          if (!user.avatarUrl && payload.picture) {
            await User.updateOne({ id: user.id }, { avatarUrl: payload.picture });
            user.avatarUrl = payload.picture;
          }
        }

        await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
        req.session.userId = user.id;
        req.session.userRole = user.role || 'user';
        logger.info({ userId: user.id, ip: req.ip, role: user.role }, '[auth] google_login_success');
        res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, username: user.username || '', role: user.role || 'user', avatarUrl: user.avatarUrl || '' } });
      } catch (err) {
        next(err);
      }
    });
  }

  // ── register ──
  if (action === 'register') {
    return authLimiter(req, res, async () => {
      try {
        const { email, password, name, username } = req.body;
        if (!email?.trim() || !password || !name?.trim()) {
          return res.status(400).json({ error: 'Name, email and password are required' });
        }
        if (password.length < 8) {
          return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
          return res.status(400).json({ error: 'Password must contain at least one uppercase letter and one number' });
        }
        if (!username?.trim()) {
          return res.status(400).json({ error: 'Username is required' });
        }
        const cleanUsername = username.toLowerCase().trim();
        if (cleanUsername.length < 3 || cleanUsername.length > 20 || !/^[a-z0-9_]+$/.test(cleanUsername)) {
          return res.status(400).json({ error: 'Username must be 3-20 chars, letters/numbers/underscores only' });
        }
        const existing = await User.findOne({ email: email.toLowerCase().trim() });
        if (existing) {
          return res.status(409).json({ error: 'An account with this email already exists' });
        }
        const takenUsername = await User.findOne({ username: cleanUsername });
        if (takenUsername) {
          return res.status(409).json({ error: 'Username already taken' });
        }
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const userId = 'user_' + uid();
        const role = ADMIN_EMAILS.includes(email.toLowerCase().trim()) ? 'superadmin' : 'user';
        const user = await User.create({ id: userId, email: email.toLowerCase().trim(), name: name.trim(), username: cleanUsername, passwordHash, role });
        await seedDefaultData(userId);
        await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
        req.session.userId = userId;
        req.session.userRole = role;
        logger.info({ userId, ip: req.ip, role }, '[auth] register_success');
        res.json({ ok: true, user: { id: userId, name: user.name, email: user.email, username: user.username, role, avatarUrl: '' } });
      } catch (err) {
        next(err);
      }
    });
  }

  // ── login ──
  if (action === 'login') {
    return authLimiter(req, res, async () => {
      try {
        const { email, password } = req.body;
        if (!email?.trim() || !password) {
          return res.status(400).json({ error: 'Email and password are required' });
        }
        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
          logger.warn({ ip: req.ip, reason: 'unknown_email' }, '[auth] login_failure');
          return res.status(401).json({ error: 'Invalid email or password' });
        }
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) {
          logger.warn({ ip: req.ip, userId: user.id, reason: 'wrong_password' }, '[auth] login_failure');
          return res.status(401).json({ error: 'Invalid email or password' });
        }
        // Auto-elevate if email is in ADMIN_EMAILS
        if (ADMIN_EMAILS.includes(user.email) && user.role !== 'superadmin') {
          await User.updateOne({ id: user.id }, { role: 'superadmin' });
          user.role = 'superadmin';
        }
        await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
        req.session.userId = user.id;
        req.session.userRole = user.role || 'user';
        logger.info({ userId: user.id, ip: req.ip, role: user.role }, '[auth] login_success');
        res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, username: user.username || '', role: user.role || 'user', avatarUrl: user.avatarUrl || '' } });
      } catch (err) {
        next(err);
      }
    });
  }

  // ── logout ──
  if (action === 'logout') {
    req.session.destroy(() => res.json({ ok: true }));
    return;
  }

  if (!req.session.userId) { res.status(401).json({ error: 'Unauthorized' }); return; }
  const userId = req.session.userId;

  // ── get_profile_stats ──
  if (action === 'get_profile_stats') {
    const user = await User.findOne({ id: userId }).select('name email username role avatarUrl createdAt -_id');
    const [projects, spaces, feedbackCount] = await Promise.all([
      Project.find({ ownerId: userId }).lean(),
      Space.find({ ownerId: userId }).lean(),
      Feedback.countDocuments({ userId }),
    ]);
    let taskTotal = 0, taskDone = 0, fileCount = 0;
    projects.forEach(p => {
      (p.tasks || []).forEach(t => { taskTotal++; if (t.done) taskDone++; });
      fileCount += (p.files || []).length;
    });
    res.json({
      user: { name: user.name, email: user.email, username: user.username || '', role: user.role, avatarUrl: user.avatarUrl || '', createdAt: user.createdAt },
      stats: {
        projectCount: projects.length,
        spaceCount: spaces.length,
        taskTotal, taskDone,
        taskOpen: taskTotal - taskDone,
        completionRate: taskTotal ? Math.round(taskDone / taskTotal * 100) : 0,
        fileCount, feedbackCount,
      },
    });
    return;
  }

  // ── update_profile ──
  if (action === 'update_profile') {
    const { name, email } = req.body;
    const updates = {};
    if (name?.trim()) updates.name = name.trim().slice(0, 100);
    if (email?.trim()) {
      const taken = await User.findOne({ email: email.toLowerCase().trim(), id: { $ne: userId } });
      if (taken) { res.status(409).json({ error: 'Email already in use' }); return; }
      updates.email = email.toLowerCase().trim();
    }
    if (!Object.keys(updates).length) { res.status(400).json({ error: 'Nothing to update' }); return; }
    await User.updateOne({ id: userId }, updates);
    res.json({ ok: true, name: updates.name, email: updates.email });
    return;
  }

  // ── upload_avatar (disk mode only — R2 uses get_upload_url + confirm_upload) ──
  if (action === 'upload_avatar') {
    if (useR2) return res.status(400).json({ error: 'R2 mode: use get_upload_url + confirm_upload' });
    if (!req.file) { res.status(400).json({ error: 'No file received' }); return; }
    const avatarUrl = filePublicUrl(`avatars/${userId}.jpg`);
    await User.updateOne({ id: userId }, { avatarUrl });
    res.json({ ok: true, avatarUrl });
    return;
  }

  // ── change_password ──
  if (action === 'change_password') {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) { res.status(400).json({ error: 'Both passwords required' }); return; }
    if (newPassword.length < 8) { res.status(400).json({ error: 'New password must be at least 8 characters' }); return; }
    const user = await User.findOne({ id: userId });
    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!match) { res.status(401).json({ error: 'Current password is incorrect' }); return; }
    await User.updateOne({ id: userId }, { passwordHash: await bcrypt.hash(newPassword, SALT_ROUNDS) });
    logger.info({ userId, ip: req.ip }, '[audit] change_password');
    // Invalidate all other active sessions so stolen cookies can't be used after a password change
    const db = mongoose.connection.db;
    const allSessions = await db.collection('sessions').find({}).toArray();
    const toDelete = allSessions
      .filter(s => { try { return JSON.parse(s.session).userId === userId; } catch { return false; } })
      .filter(s => s._id.toString() !== req.sessionID)
      .map(s => s._id);
    if (toDelete.length) await db.collection('sessions').deleteMany({ _id: { $in: toDelete } });
    res.json({ ok: true });
    return;
  }

  // ── delete_account ──
  if (action === 'delete_account') {
    const { password } = req.body;
    if (!password) { res.status(400).json({ error: 'Password required' }); return; }
    const user = await User.findOne({ id: userId });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) { res.status(401).json({ error: 'Incorrect password' }); return; }
    // Delete all stored files before removing documents
    const userProjects = await Project.find({ ownerId: userId }).select('files tasks').lean();
    logger.info({ userId, ip: req.ip, projectCount: userProjects.length }, '[audit] delete_account');
    await deleteUserFiles(userId, userProjects);
    await Promise.all([
      User.deleteOne({ id: userId }),
      Project.deleteMany({ ownerId: userId }),
      Space.deleteMany({ ownerId: userId }),
      Feedback.deleteMany({ userId }),
      // Remove this user from collaborator lists on projects/spaces they didn't own
      Project.updateMany({ 'collaborators.userId': userId }, { $pull: { collaborators: { userId } } }),
      Space.updateMany({ 'collaborators.userId': userId }, { $pull: { collaborators: { userId } } }),
      // Remove pending notifications to/from this user
      Notification.deleteMany({ $or: [{ toUserId: userId }, { fromUserId: userId }] }),
    ]);
    req.session.destroy(() => res.json({ ok: true }));
    return;
  }

  // ── export_data ──
  if (action === 'export_data') {
    return exportLimiter(req, res, async () => {
      const [projects, spaces] = await Promise.all([
        Project.find({ ownerId: userId }).select('-_id -__v').lean(),
        Space.find({ ownerId: userId }).select('-_id -__v').lean(),
      ]);
      res.json({ spaces, projects, exportedAt: new Date().toISOString() });
    });
  }

  // ── post_feedback ──
  if (action === 'post_feedback') {
    const { message, type = 'general' } = req.body;
    if (!message?.trim()) { res.status(400).json({ error: 'Message required' }); return; }
    const user = await User.findOne({ id: userId }).select('name -_id');
    const item = await Feedback.create({
      id: 'fb_' + uid(),
      userId,
      userName: user?.name || 'Anonymous',
      message: message.trim().slice(0, 500),
      type: ['bug','idea','general'].includes(type) ? type : 'general',
      status: 'open',
      upvotes: [],
    });
    const { _id, __v, upvotes, ...rest } = item.toObject();
    res.json({ ok: true, item: { ...rest, upvoteCount: 0, hasUpvoted: false } });
    return;
  }

  // ── toggle_feedback_status ──
  if (action === 'toggle_feedback_status') {
    if (req.session.userRole !== 'superadmin') { res.status(403).json({ error: 'Forbidden' }); return; }
    const { feedbackId } = req.body;
    const item = await Feedback.findOne({ id: feedbackId });
    if (!item) { res.status(404).json({ error: 'Not found' }); return; }
    item.status = item.status === 'open' ? 'fixed' : 'open';
    await item.save();
    res.json({ ok: true, status: item.status });
    return;
  }

  // ── upvote_feedback ──
  if (action === 'upvote_feedback') {
    const { feedbackId } = req.body;
    const existing = await Feedback.findOne({ id: feedbackId }).select('upvotes -_id').lean();
    if (!existing) { res.status(404).json({ error: 'Not found' }); return; }
    const alreadyUpvoted = existing.upvotes.includes(userId);
    const updated = await Feedback.findOneAndUpdate(
      { id: feedbackId },
      alreadyUpvoted ? { $pull: { upvotes: userId } } : { $addToSet: { upvotes: userId } },
      { new: true, select: 'upvotes -_id' }
    );
    res.json({ ok: true, upvoteCount: updated.upvotes.length, hasUpvoted: !alreadyUpvoted });
    return;
  }

  // ── add_project ──
  if (action === 'add_project') {
    const { title, subtitle = '', color = '#888785', tag = 'Project', spaceId = '' } = req.body;
    if (!title?.trim()) { res.status(400).json({ error: 'Title required' }); return; }
    if (!isValidColor(color)) { res.status(400).json({ error: 'Invalid color format' }); return; }
    const totalProjects = await Project.countDocuments({ ownerId: userId });
    if (totalProjects >= 200) { res.status(429).json({ error: 'Project limit reached (200 max)' }); return; }
    if (spaceId) {
      const ownedSpace = await Space.findOne({ id: spaceId, ownerId: userId });
      if (!ownedSpace) {
        const editorSpace = await Space.findOne({ id: spaceId, collaborators: { $elemMatch: { userId, role: 'editor' } } });
        if (!editorSpace) { res.status(403).json({ error: 'No editor access to this space' }); return; }
      }
    }
    const newId = 'proj_' + uid();
    const count = await Project.countDocuments({ spaceId, ownerId: userId });
    const initialCollaborators = [];
    // If creating in a space the user doesn't own, auto-add the space owner as editor collaborator
    if (spaceId) {
      const parentSpace = await Space.findOne({ id: spaceId, ownerId: { $ne: userId } }).select('ownerId -_id').lean();
      if (parentSpace) {
        const spaceOwner = await User.findOne({ id: parentSpace.ownerId }).select('id name email username avatarUrl -_id').lean();
        if (spaceOwner) {
          initialCollaborators.push({ id: 'collab_' + uid(), userId: spaceOwner.id, name: spaceOwner.name, email: spaceOwner.email || '', username: spaceOwner.username || '', avatarUrl: spaceOwner.avatarUrl || '', role: 'editor', status: 'active' });
        }
      }
    }
    await Project.create({ id: newId, title: title.trim().slice(0, 200), subtitle: subtitle.toString().trim().slice(0, 300), color, tag: tag.toString().trim().slice(0, 50) || 'Project', spaceId, ownerId: userId, tasks: [], notes: '', richNotes: '', files: [], collaborators: initialCollaborators, __orderRank: count });
    res.json({ ok: true, id: newId });
    return;
  }

  // ── rename_project ──
  if (action === 'rename_project') {
    const { projectId, title, subtitle, tag, color } = req.body;
    if (!projectId || !title?.trim()) { res.status(400).json({ error: 'Missing data' }); return; }
    const update = { title: title.trim().slice(0, 200) };
    if (subtitle !== undefined) update.subtitle = subtitle.toString().trim().slice(0, 300);
    if (tag !== undefined) update.tag = tag.toString().trim().slice(0, 50) || 'Project';
    if (color !== undefined) {
      if (!isValidColor(color)) { res.status(400).json({ error: 'Invalid color format' }); return; }
      update.color = color;
    }
    await Project.updateOne({ id: projectId, ownerId: userId }, { $set: update });
    res.json({ ok: true });
    return;
  }

  // ── duplicate_project ──
  if (action === 'duplicate_project') {
    const { projectId } = req.body;
    const source = await Project.findOne({ id: projectId, ownerId: userId }).lean();
    if (!source) { res.status(404).json({ error: 'Project not found' }); return; }
    const dupId = 'proj_' + uid();
    const { _id, __v, id, ...rest } = source;
    await Project.create({
      ...rest,
      id: dupId,
      title: (rest.title || 'Project') + ' Copy',
      ownerId: userId,
      files: [],
      tasks: (rest.tasks || []).map(cloneTaskForDuplicate),
    });
    res.json({ ok: true, id: dupId });
    return;
  }

  // ── copy_project (cross-space copy) ──
  if (action === 'copy_project') {
    const { projectId, spaceId: targetSpaceId } = req.body;
    if (!projectId || !targetSpaceId) { res.status(400).json({ error: 'Missing data' }); return; }
    const source = await Project.findOne({ id: projectId, ownerId: userId }).lean();
    if (!source) { res.status(404).json({ error: 'Project not found' }); return; }
    const space = await Space.findOne({ id: targetSpaceId, ownerId: userId });
    if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
    const { _id, __v, id, ...rest } = source;
    const newId = 'proj_' + uid();
    await Project.create({
      ...rest,
      id: newId,
      spaceId: targetSpaceId,
      title: (rest.title || 'Project') + ' (Copy)',
      ownerId: userId,
      files: [],
      tasks: (rest.tasks || []).map(cloneTaskForDuplicate),
    });
    res.json({ ok: true, id: newId });
    return;
  }

  // ── move_project (cross-space move) ──
  if (action === 'move_project') {
    const { projectId, spaceId: targetSpaceId } = req.body;
    if (!projectId || !targetSpaceId) { res.status(400).json({ error: 'Missing data' }); return; }
    const proj = await Project.findOne({ id: projectId, ownerId: userId });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const space = await Space.findOne({ id: targetSpaceId, ownerId: userId });
    if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
    proj.spaceId = targetSpaceId;
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── delete_project ──
  if (action === 'delete_project') {
    const { projectId } = req.body;
    const proj = await Project.findOne({ id: projectId, ownerId: userId }).lean();
    if (proj) {
      logger.info({ userId, projectId, title: proj.title, taskCount: (proj.tasks || []).length }, '[audit] delete_project');
      for (const f of proj.files || []) await deleteStoredFile(f);
      for (const t of proj.tasks || []) { for (const f of t.files || []) await deleteStoredFile(f); }
    }
    await Project.deleteOne({ id: projectId, ownerId: userId });
    res.json({ ok: true });
    return;
  }

  // ── archive_project ──
  if (action === 'archive_project') {
    const { projectId } = req.body;
    await Project.updateOne({ id: projectId, ownerId: userId }, { $set: { archived: true } });
    res.json({ ok: true });
    return;
  }

  // ── unarchive_project ──
  if (action === 'unarchive_project') {
    const { projectId } = req.body;
    await Project.updateOne({ id: projectId, ownerId: userId }, { $set: { archived: false } });
    res.json({ ok: true });
    return;
  }

  // ── clear_project_tasks ──
  if (action === 'clear_project_tasks') {
    const { projectId } = req.body;
    const proj = await Project.findOne({ id: projectId, ownerId: userId });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    logger.info({ userId, projectId, taskCount: proj.tasks.length }, '[audit] clear_project_tasks');
    for (const t of proj.tasks || []) { for (const f of t.files || []) await deleteStoredFile(f); }
    proj.tasks = [];
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── invite_collaborator ──
  if (action === 'invite_collaborator') {
    const { projectId, name = '', email, role = 'editor' } = req.body;
    if (!projectId || !email?.trim()) { res.status(400).json({ error: 'Missing data' }); return; }
    if (!VALID_COLLAB_ROLES.includes(role)) { res.status(400).json({ error: 'Invalid role' }); return; }
    const proj = await Project.findOne({ id: projectId, ownerId: userId });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const exists = proj.collaborators.some(c => c.email.toLowerCase() === email.toLowerCase());
    if (exists) { res.status(400).json({ error: 'Collaborator already exists' }); return; }
    const collab = { id: 'collab_' + uid(), name: name.trim().slice(0, 100) || email.replace(/@.*/, ''), email: email.trim(), role, status: 'invited' };
    proj.collaborators.push(collab);
    await proj.save();
    const inviter = await User.findOne({ id: userId }).select('name -_id');
    sendInviteEmail({ to: email.trim(), toName: name.trim(), inviterName: inviter?.name || 'Someone', projectTitle: proj.title });
    res.json({ ok: true, collaborator: collab });
    return;
  }

  // ── remove_collaborator ──
  if (action === 'remove_collaborator') {
    const { projectId, collaboratorId } = req.body;
    const proj = await Project.findOne({ id: projectId, ownerId: userId });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    logger.info({ userId, projectId, collaboratorId }, '[audit] remove_collaborator');
    proj.collaborators = proj.collaborators.filter(c => c.id !== collaboratorId);
    proj.tasks.forEach(t => {
      if (t.assignee === collaboratorId) t.assignee = '';
      if (Array.isArray(t.assignees)) t.assignees = t.assignees.filter(a => a !== collaboratorId);
    });
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── update_collaborator_role ──
  if (action === 'update_collaborator_role') {
    const { projectId, collaboratorId, role } = req.body;
    if (!projectId || !collaboratorId || !role) { res.status(400).json({ error: 'Missing data' }); return; }
    if (!VALID_COLLAB_ROLES.includes(role)) { res.status(400).json({ error: 'Invalid role' }); return; }
    const proj = await Project.findOne({ id: projectId, ownerId: userId });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const collab = proj.collaborators.find(c => c.id === collaboratorId);
    if (!collab) { res.status(404).json({ error: 'Collaborator not found' }); return; }
    collab.role = role;
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── task_toggle ──
  if (action === 'task_toggle') {
    const { projectId, taskId } = req.body;
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const task = proj.tasks.find(t => t.id === taskId);
    if (task) { task.done = !task.done; task.finishedAt = task.done ? new Date() : null; }
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── add_task ──
  if (action === 'add_task') {
    const { projectId, text } = req.body;
    if (!text?.trim()) { res.status(400).json({ error: 'Empty task' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    if (proj.tasks.length >= 1000) { res.status(429).json({ error: 'Task limit reached (1000 per project)' }); return; }
    const newId = 'task_' + uid();
    proj.tasks.push({ id: newId, text: text.trim().slice(0, 500), done: false, badge: 'Custom', notes: '', richNotes: '', files: [], deadline: '', assignee: '', assignees: [], priority: '', comments: [] });
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true, id: newId });
    return;
  }

  // ── rename_task ──
  if (action === 'rename_task') {
    const { projectId, taskId, text } = req.body;
    if (!text?.trim()) { res.status(400).json({ error: 'Empty task' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const task = proj.tasks.find(t => t.id === taskId);
    if (task) task.text = text.trim().slice(0, 500);
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── update_task_meta ──
  if (action === 'update_task_meta') {
    const { projectId, taskId, deadline, assignee, assignees, priority, badge } = req.body;
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const task = proj.tasks.find(t => t.id === taskId);
    let prevAssignees = [];
    if (task) {
      prevAssignees = [...(task.assignees || [])];
      if (deadline  !== undefined) task.deadline  = deadline.trim();
      if (assignee  !== undefined) task.assignee  = assignee.trim();
      if (assignees !== undefined) task.assignees = Array.isArray(assignees) ? assignees : [];
      if (priority  !== undefined) task.priority  = priority.trim();
      if (badge     !== undefined) task.badge     = badge;
    }
    await proj.save();
    // Notify newly assigned users
    if (task && assignees !== undefined) {
      const prevSet = new Set(prevAssignees);
      const newlyAdded = (task.assignees || []).filter(a => !prevSet.has(a) && a !== 'me');
      if (newlyAdded.length) {
        const assigner = await User.findOne({ id: userId }).select('name username avatarUrl -_id');
        const notifDocs = [];
        for (const aid of newlyAdded) {
          const collab = proj.collaborators.find(c => c.id === aid);
          if (!collab?.userId || collab.userId === userId) continue;
          notifDocs.push({
            id: 'notif_' + uid(), toUserId: collab.userId, fromUserId: userId,
            fromUsername: assigner.username || '', fromName: assigner.name, fromAvatarUrl: assigner.avatarUrl || '',
            type: 'task_assigned',
            meta: { entityId: projectId, entityType: 'project', entityTitle: proj.title, taskId: task.id, taskTitle: task.text?.slice(0, 60) || '' },
            status: 'pending',
          });
        }
        if (notifDocs.length) await Notification.insertMany(notifDocs);
      }
    }
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── delete_task ──
  if (action === 'delete_task') {
    const { projectId, taskId } = req.body;
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const tIdx = proj.tasks.findIndex(t => t.id === taskId);
    if (tIdx > -1) {
      for (const f of proj.tasks[tIdx].files || []) await deleteStoredFile(f);
      proj.tasks.splice(tIdx, 1);
      await proj.save();
    }
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── restore_task ──
  if (action === 'restore_task') {
    const { projectId, task } = req.body;
    if (!task?.id || !task?.text) { res.status(400).json({ error: 'Invalid task' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const taskId_raw = String(task.id);
    const idCollision = proj.tasks.some(t => t.id === taskId_raw);
    const safeTask = {
      id: idCollision ? 'task_' + uid() : taskId_raw,
      text: String(task.text).trim().slice(0, 1000),
      done: Boolean(task.done),
      priority: ['urgent', 'important', 'later', ''].includes(task.priority) ? task.priority : '',
      deadline: task.deadline || '',
      badge: String(task.badge || 'Custom').slice(0, 50),
      assignees: Array.isArray(task.assignees) ? task.assignees.map(String) : [],
      comments: [],
      notes: '', richNotes: '', files: [],
    };
    proj.tasks.push(safeTask);
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── save_notes ──
  if (action === 'save_notes') {
    const { projectId, notes = '' } = req.body;
    if (Buffer.byteLength(notes, 'utf8') > 200 * 1024) { res.status(413).json({ error: 'Notes too large (max 200KB)' }); return; }
    await Project.updateOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $set: { notes } });
    res.json({ ok: true });
    return;
  }

  // ── save_project_rich_notes ──
  if (action === 'save_project_rich_notes') {
    const { projectId, notes = '' } = req.body;
    if (Buffer.byteLength(notes, 'utf8') > 200 * 1024) { res.status(413).json({ error: 'Notes too large (max 200KB)' }); return; }
    await Project.updateOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $set: { richNotes: notes } });
    res.json({ ok: true });
    return;
  }

  // ── save_task_notes ──
  if (action === 'save_task_notes') {
    const { projectId, taskId, notes = '' } = req.body;
    if (Buffer.byteLength(notes, 'utf8') > 200 * 1024) { res.status(413).json({ error: 'Notes too large (max 200KB)' }); return; }
    await Project.updateOne({ id: projectId, 'tasks.id': taskId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $set: { 'tasks.$.notes': notes } });
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── save_task_rich_notes ──
  if (action === 'save_task_rich_notes') {
    const { projectId, taskId, notes = '' } = req.body;
    if (Buffer.byteLength(notes, 'utf8') > 200 * 1024) { res.status(413).json({ error: 'Notes too large (max 200KB)' }); return; }
    await Project.updateOne({ id: projectId, 'tasks.id': taskId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $set: { 'tasks.$.richNotes': notes } });
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── reorder_projects ──
  if (action === 'reorder_projects') {
    const { order } = req.body;
    if (!Array.isArray(order) || order.length > 500) { res.status(400).json({ error: 'Invalid order' }); return; }
    const ops = order.map((id, index) => ({
      updateOne: { filter: { id, ownerId: userId }, update: { $set: { __orderRank: index } } }
    }));
    if (ops.length) await Project.collection.bulkWrite(ops);
    res.json({ ok: true });
    return;
  }

  // ── confirm_upload (R2 mode: browser finished uploading to R2, save metadata to DB) ──
  if (action === 'confirm_upload') {
    const { fileId, fileKey, filename, mimeType, size, type, projectId, taskId } = req.body;
    if (!fileId || !fileKey || !filename || !type) { return res.status(400).json({ error: 'Missing required fields' }); }
    const ext = path.extname(filename).toLowerCase().replace('.', '');
    const fe = { id: fileId, name: filename, file: fileKey, url: filePublicUrl(fileKey), type: ext, size: Number(size) || 0, uploaded: now() };

    if (type === 'avatar') {
      await User.updateOne({ id: userId }, { avatarUrl: fe.url });
      logger.info({ userId, fileKey }, '[upload] avatar confirmed');
      return res.json({ ok: true, avatarUrl: fe.url });
    }
    if (type === 'task') {
      if (!projectId || !taskId) return res.status(400).json({ error: 'projectId and taskId required' });
      const result = await Project.updateOne(
        { id: projectId, 'tasks.id': taskId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] },
        { $push: { 'tasks.$.files': fe } },
      );
      if (result.matchedCount === 0) return res.status(403).json({ error: 'No access' });
      logger.info({ userId, fileId, fileKey, projectId, taskId }, '[upload] task file confirmed');
      return res.json({ ok: true, file: fe });
    }
    // type === 'project'
    if (!projectId) return res.status(400).json({ error: 'projectId required' });
    const result = await Project.updateOne(
      { id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] },
      { $push: { files: fe } },
    );
    if (result.matchedCount === 0) return res.status(403).json({ error: 'No access' });
    logger.info({ userId, fileId, fileKey, projectId }, '[upload] project file confirmed');
    return res.json({ ok: true, file: fe });
  }

  // ── upload (project-level, disk mode only) ──
  if (action === 'upload') {
    if (useR2) return res.status(400).json({ error: 'R2 mode: use get_upload_url + confirm_upload' });
    const pid = req.body.projectId;
    if (!pid || !req.file) { res.status(400).json({ error: !pid ? 'Missing projectId' : 'No file received' }); return; }
    const ext = path.extname(req.file.originalname).toLowerCase().replace('.', '');
    const fe = { id: uid(), name: req.file.originalname, file: req.file.filename, url: filePublicUrl(req.file.filename), type: ext, size: req.file.size, uploaded: now() };
    const result = await Project.updateOne({ id: pid, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $push: { files: fe } });
    if (result.matchedCount === 0) { res.status(403).json({ error: 'Project not found or no editor access' }); return; }
    res.json({ ok: true, file: fe });
    return;
  }

  // ── upload_task_file (disk mode only) ──
  if (action === 'upload_task_file') {
    if (useR2) return res.status(400).json({ error: 'R2 mode: use get_upload_url + confirm_upload' });
    const { projectId, taskId } = req.body;
    if (!projectId || !taskId || !req.file) { res.status(400).json({ error: !projectId ? 'Missing projectId' : !taskId ? 'Missing taskId' : 'No file received' }); return; }
    const ext = path.extname(req.file.originalname).toLowerCase().replace('.', '');
    const fe = { id: uid(), name: req.file.originalname, file: req.file.filename, url: filePublicUrl(req.file.filename), type: ext, size: req.file.size, uploaded: now() };
    const result = await Project.updateOne({ id: projectId, 'tasks.id': taskId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] }, { $push: { 'tasks.$.files': fe } });
    if (result.matchedCount === 0) { res.status(403).json({ error: 'Project not found or no editor access' }); return; }
    res.json({ ok: true, file: fe });
    return;
  }

  // ── delete_file (project-level) ──
  if (action === 'delete_file') {
    const { projectId, fileId } = req.body;
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const f = proj.files.find(x => x.id === fileId);
    if (f) await deleteStoredFile(f);
    proj.files = proj.files.filter(x => x.id !== fileId);
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── delete_task_file ──
  if (action === 'delete_task_file') {
    const { projectId, taskId, fileId } = req.body;
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const task = proj.tasks.find(t => t.id === taskId);
    if (task) {
      const f = task.files.find(x => x.id === fileId);
      if (f) await deleteStoredFile(f);
      task.files = task.files.filter(x => x.id !== fileId);
    }
    await proj.save();
    res.json({ ok: true });
    return;
  }

  // ── add_space ──
  if (action === 'add_space') {
    const { title, icon = '📁', color = '#6366f1', description = '' } = req.body;
    if (!title?.trim()) { res.status(400).json({ error: 'Title required' }); return; }
    if (!isValidColor(color)) { res.status(400).json({ error: 'Invalid color format' }); return; }
    const count = await Space.countDocuments({ ownerId: userId });
    if (count >= 50) { res.status(429).json({ error: 'Space limit reached (50 max)' }); return; }
    const newId = 'space_' + uid();
    await Space.create({ id: newId, title: title.trim().slice(0, 200), icon: safeIcon(icon), color, description: description.toString().slice(0, 500), ownerId: userId, __orderRank: count });
    res.json({ ok: true, id: newId });
    return;
  }

  // ── rename_space ──
  if (action === 'rename_space') {
    const { spaceId, title, icon, color, description } = req.body;
    if (!spaceId) { res.status(400).json({ error: 'Missing spaceId' }); return; }
    const update = {};
    if (title !== undefined) update.title = title.toString().trim().slice(0, 200);
    if (icon !== undefined) update.icon = safeIcon(icon);
    if (color !== undefined) {
      if (!isValidColor(color)) { res.status(400).json({ error: 'Invalid color format' }); return; }
      update.color = color;
    }
    if (description !== undefined) update.description = description.toString().slice(0, 500);
    await Space.updateOne({ id: spaceId, ownerId: userId }, { $set: update });
    res.json({ ok: true });
    return;
  }

  // ── delete_space ──
  if (action === 'delete_space') {
    const { spaceId } = req.body;
    if (!spaceId) { res.status(400).json({ error: 'Missing spaceId' }); return; }
    const spaceProjects = await Project.find({ spaceId, ownerId: userId }).lean();
    logger.info({ userId, spaceId, projectCount: spaceProjects.length }, '[audit] delete_space');
    for (const p of spaceProjects) {
      for (const f of p.files || []) await deleteStoredFile(f);
      for (const t of p.tasks || []) { for (const f of t.files || []) await deleteStoredFile(f); }
      await Project.deleteOne({ id: p.id, ownerId: userId });
    }
    await Space.deleteOne({ id: spaceId, ownerId: userId });
    res.json({ ok: true });
    return;
  }

  // ── invite_space_collaborator ──
  if (action === 'invite_space_collaborator') {
    const { spaceId, name = '', email, role = 'editor' } = req.body;
    if (!spaceId || !email?.trim()) { res.status(400).json({ error: 'Missing data' }); return; }
    if (!VALID_COLLAB_ROLES.includes(role)) { res.status(400).json({ error: 'Invalid role' }); return; }
    const space = await Space.findOne({ id: spaceId, ownerId: userId });
    if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
    const exists = (space.collaborators || []).some(c => c.email?.toLowerCase() === email.toLowerCase());
    if (exists) { res.status(400).json({ error: 'Collaborator already exists' }); return; }
    space.collaborators.push({ id: crypto.randomUUID(), name: (name.trim() || email.replace(/@.*/, '')), email: email.trim(), role });
    await space.save();
    const inviter = await User.findOne({ id: userId }).select('name -_id');
    sendInviteEmail({ to: email.trim(), toName: name.trim(), inviterName: inviter?.name || 'Someone', spaceTitle: space.title });
    res.json({ ok: true });
    return;
  }

  // ── update_space_collaborator_role ──
  if (action === 'update_space_collaborator_role') {
    const { spaceId, collaboratorId, role } = req.body;
    if (!spaceId || !collaboratorId || !role) { res.status(400).json({ error: 'Missing data' }); return; }
    if (!VALID_COLLAB_ROLES.includes(role)) { res.status(400).json({ error: 'Invalid role' }); return; }
    const space = await Space.findOne({ id: spaceId, ownerId: userId });
    if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
    const collab = space.collaborators.find(c => c.id === collaboratorId);
    if (!collab) { res.status(404).json({ error: 'Collaborator not found' }); return; }
    collab.role = role;
    await space.save();
    res.json({ ok: true });
    return;
  }

  // ── remove_space_collaborator ──
  if (action === 'remove_space_collaborator') {
    const { spaceId, collaboratorId } = req.body;
    if (!spaceId || !collaboratorId) { res.status(400).json({ error: 'Missing data' }); return; }
    const space = await Space.findOne({ id: spaceId, ownerId: userId });
    if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
    space.collaborators = space.collaborators.filter(c => c.id !== collaboratorId);
    await space.save();
    res.json({ ok: true });
    return;
  }

  // ── send_collab_invite ──
  if (action === 'send_collab_invite') {
    const { email, entityId, entityType, role } = req.body;
    if (!email || !entityId || !entityType || !role) { res.status(400).json({ error: 'Missing fields' }); return; }
    if (!['project', 'space'].includes(entityType)) { res.status(400).json({ error: 'Invalid entity type' }); return; }
    if (!VALID_COLLAB_ROLES.includes(role)) { res.status(400).json({ error: 'Invalid role' }); return; }
    const cleanEmail = email.toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) { res.status(400).json({ error: 'Invalid email address' }); return; }
    let entityTitle = '';
    if (entityType === 'project') {
      const proj = await Project.findOne({ id: entityId, ownerId: userId }).select('title collaborators -_id');
      if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
      entityTitle = proj.title;
      const target = await User.findOne({ email: cleanEmail }).select('id -_id');
      if (target && proj.collaborators.some(c => c.userId === target.id)) { res.status(409).json({ error: 'User is already a collaborator' }); return; }
    } else {
      const space = await Space.findOne({ id: entityId, ownerId: userId }).select('title collaborators -_id');
      if (!space) { res.status(404).json({ error: 'Space not found' }); return; }
      entityTitle = space.title;
      const target = await User.findOne({ email: cleanEmail }).select('id -_id');
      if (target && space.collaborators.some(c => c.userId === target.id)) { res.status(409).json({ error: 'User is already a collaborator' }); return; }
    }
    const target = await User.findOne({ email: cleanEmail }).select('id name username email avatarUrl -_id');
    const fromUser = await User.findOne({ id: userId }).select('name username avatarUrl -_id');

    // Create a direct invitation token
    const token = crypto.randomBytes(16).toString('hex');
    await Invitation.create({
      token,
      email: cleanEmail,
      entityId,
      entityType,
      role,
      inviterName: fromUser.name
    });

    if (!target) {
      await sendInviteEmail({
        to: cleanEmail,
        toName: '',
        inviterName: fromUser.name,
        projectTitle: entityType === 'project' ? entityTitle : null,
        spaceTitle: entityType === 'space' ? entityTitle : null,
        inviteToken: token
      });
      res.json({ ok: true, notFound: true, invitedName: cleanEmail });
      return;
    }
    if (target.id === userId) { res.status(400).json({ error: 'Cannot invite yourself' }); return; }
    const alreadyPending = await Notification.findOne({ toUserId: target.id, fromUserId: userId, type: 'collab_invite', 'meta.entityId': entityId, status: 'pending' });
    if (alreadyPending) { res.status(409).json({ error: 'Invite already pending for this user' }); return; }
    // Prevent notification-inbox flooding: cap pending invites per target at 50
    const pendingCount = await Notification.countDocuments({ toUserId: target.id, type: 'collab_invite', status: 'pending' });
    if (pendingCount >= 50) { res.status(429).json({ error: 'This user has too many pending invites. Try again later.' }); return; }
    
    await Notification.create({
      id: 'notif_' + uid(), toUserId: target.id, fromUserId: userId,
      fromUsername: fromUser.username, fromName: fromUser.name, fromAvatarUrl: fromUser.avatarUrl || '',
      type: 'collab_invite',
      meta: { entityId, entityType, entityTitle, role },
      status: 'pending',
    });

    await sendInviteEmail({
      to: cleanEmail,
      toName: target.name,
      inviterName: fromUser.name,
      projectTitle: entityType === 'project' ? entityTitle : null,
      spaceTitle: entityType === 'space' ? entityTitle : null,
      inviteToken: token
    });

    res.json({ ok: true, invitedName: target.name });
    return;
  }

  // ── join_via_link ──
  if (action === 'join_via_link') {
    const { token } = req.body;
    if (!token) { res.status(400).json({ error: 'Missing token' }); return; }

    const directInvite = await Invitation.findOne({ token });
    if (directInvite) {
      const { entityId, entityType, role } = directInvite;
      let entity;
      if (entityType === 'project') {
        entity = await Project.findOne({ id: entityId });
      } else {
        entity = await Space.findOne({ id: entityId });
      }
      if (!entity) {
        await Invitation.deleteOne({ token });
        res.status(404).json({ error: 'Invited project or space no longer exists' });
        return;
      }
      if (entity.ownerId === userId) {
        await Invitation.deleteOne({ token });
        res.json({ ok: true, alreadyOwner: true, entityType, entityId, entityTitle: entity.title, role: 'owner' });
        return;
      }
      if ((entity.collaborators || []).some(c => c.userId === userId)) {
        await Invitation.deleteOne({ token });
        res.json({ ok: true, alreadyMember: true, entityType, entityId, entityTitle: entity.title, role: (entity.collaborators.find(c => c.userId === userId))?.role || role });
        return;
      }
      const me = await User.findOne({ id: userId }).select('id name username email avatarUrl -_id');
      const collabEntry = { id: 'c_' + uid(), userId: me.id, name: me.name, username: me.username || '', email: me.email || '', role, avatarUrl: me.avatarUrl || '' };
      
      if (entityType === 'project') {
        await Project.updateOne({ id: entityId }, { $push: { collaborators: collabEntry } });
      } else {
        await Space.updateOne({ id: entityId }, { $push: { collaborators: collabEntry } });
      }
      await Invitation.deleteOne({ token });
      await Notification.create({
        id: 'notif_' + uid(), toUserId: entity.ownerId, fromUserId: userId,
        fromUsername: me.username || '', fromName: me.name, fromAvatarUrl: me.avatarUrl || '',
        type: 'invite_response',
        meta: { entityId: entityId, entityType, entityTitle: entity.title, role, accepted: true },
        status: 'pending',
      });
      res.json({ ok: true, entityType, entityId, entityTitle: entity.title, role });
      return;
    }

    let entity = await Project.findOne({ inviteToken: token }).lean();
    let entityType = entity ? 'project' : null;
    if (!entity) {
      entity = await Space.findOne({ inviteToken: token }).lean();
      entityType = entity ? 'space' : null;
    }
    if (!entity) { res.status(404).json({ error: 'Invalid or expired invite link' }); return; }
    if (entity.inviteTokenExpiry && new Date(entity.inviteTokenExpiry) < new Date()) {
      res.status(410).json({ error: 'Invite link has expired' }); return;
    }
    if (entity.ownerId === userId) { res.json({ ok: true, alreadyOwner: true, entityType, entityId: entity.id, entityTitle: entity.title, role: 'owner' }); return; }
    if ((entity.collaborators || []).some(c => c.userId === userId)) { res.json({ ok: true, alreadyMember: true, entityType, entityId: entity.id, entityTitle: entity.title, role: (entity.collaborators.find(c => c.userId === userId))?.role || 'editor' }); return; }
    const me = await User.findOne({ id: userId }).select('id name username email avatarUrl -_id');
    const role = entity.inviteLinkRole || 'editor';
    const collabEntry = { id: 'c_' + uid(), userId: me.id, name: me.name, username: me.username || '', email: me.email || '', role, avatarUrl: me.avatarUrl || '' };
    const clearToken = { $unset: { inviteToken: '', inviteTokenExpiry: '' } };
    if (entityType === 'project') {
      await Project.updateOne({ id: entity.id }, { $push: { collaborators: collabEntry }, ...clearToken });
    } else {
      await Space.updateOne({ id: entity.id }, { $push: { collaborators: collabEntry }, ...clearToken });
    }
    await Notification.create({
      id: 'notif_' + uid(), toUserId: entity.ownerId, fromUserId: userId,
      fromUsername: me.username || '', fromName: me.name, fromAvatarUrl: me.avatarUrl || '',
      type: 'invite_response',
      meta: { entityId: entity.id, entityType, entityTitle: entity.title, role, accepted: true },
      status: 'pending',
    });
    res.json({ ok: true, entityType, entityId: entity.id, entityTitle: entity.title, role });
    return;
  }

  // ── respond_collab_invite ──
  if (action === 'respond_collab_invite') {
    const { notifId, accept } = req.body;
    const notif = await Notification.findOne({ id: notifId, toUserId: userId, type: 'collab_invite', status: 'pending' });
    if (!notif) { res.status(404).json({ error: 'Invite not found or already handled' }); return; }
    notif.status = accept ? 'accepted' : 'denied';
    await notif.save();
    const me = await User.findOne({ id: userId }).select('id name username email avatarUrl -_id');
    if (accept) {
      const collabEntry = { id: 'c_' + uid(), userId: me.id, name: me.name, username: me.username || '', email: me.email || '', role: notif.meta.role, avatarUrl: me.avatarUrl || '' };
      if (notif.meta.entityType === 'project') {
        await Project.updateOne({ id: notif.meta.entityId }, { $push: { collaborators: collabEntry } });
      } else {
        await Space.updateOne({ id: notif.meta.entityId }, { $push: { collaborators: collabEntry } });
      }
    }
    // Notify the inviter of the response (accept or deny)
    if (notif.fromUserId) {
      await Notification.create({
        id: 'notif_' + uid(), toUserId: notif.fromUserId, fromUserId: userId,
        fromUsername: me.username || '', fromName: me.name, fromAvatarUrl: me.avatarUrl || '',
        type: 'invite_response',
        meta: { entityId: notif.meta.entityId, entityType: notif.meta.entityType, entityTitle: notif.meta.entityTitle, role: notif.meta.role, accepted: accept },
        status: 'pending',
      });
    }
    res.json({ ok: true, accepted: accept });
    return;
  }

  // ── mark_notification_read ──
  if (action === 'mark_notification_read') {
    const { notifId } = req.body || {};
    if (notifId) {
      await Notification.updateOne({ id: notifId, toUserId: userId }, { status: 'read' });
    } else {
      // Mark all read except pending collab invites (user still needs to respond to those)
      await Notification.updateMany(
        { toUserId: userId, $or: [{ type: { $ne: 'collab_invite' } }, { status: { $ne: 'pending' } }] },
        { status: 'read' }
      );
    }
    res.json({ ok: true });
    return;
  }

  // ── set_username ──
  if (action === 'set_username') {
    const { username } = req.body;
    const me = await User.findOne({ id: userId });
    if (!me) { res.status(404).json({ error: 'User not found' }); return; }
    if (me.username) { res.status(409).json({ error: 'Username already set and cannot be changed' }); return; }
    const raw = (username || '').toLowerCase().trim();
    if (!raw || raw.length < 3) { res.status(400).json({ error: 'Username must be at least 3 characters' }); return; }
    if (raw.length > 20) { res.status(400).json({ error: 'Username must be 20 characters or less' }); return; }
    if (!/^[a-z0-9_]+$/.test(raw)) { res.status(400).json({ error: 'Only letters, numbers and _ allowed' }); return; }
    const exists = await User.findOne({ username: raw });
    if (exists) { res.status(409).json({ error: 'Username already taken' }); return; }
    me.username = raw;
    await me.save();
    res.json({ ok: true, username: raw });
    return;
  }

  // ── add_task_comment ──
  if (action === 'add_task_comment') {
    const { projectId, taskId, text, mentions = [] } = req.body;
    if (!projectId || !taskId || !text?.trim()) { res.status(400).json({ error: 'Missing data' }); return; }
    const safeMentions = Array.isArray(mentions) ? mentions.slice(0, 20).map(String) : [];
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { 'collaborators.userId': userId }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const taskForCap = proj.tasks.find(t => t.id === taskId);
    if (!taskForCap) { res.status(404).json({ error: 'Task not found' }); return; }
    if ((taskForCap.comments || []).length >= 500) { res.status(429).json({ error: 'Comment limit reached (500 per task)' }); return; }
    const me = await User.findOne({ id: userId }).select('name username avatarUrl -_id');
    const comment = { id: 'cmt_' + uid(), userId, username: me.username || '', name: me.name, avatarUrl: me.avatarUrl || '', text: text.trim().slice(0, 1000), mentions: safeMentions, createdAt: new Date() };
    await Project.updateOne({ id: projectId, 'tasks.id': taskId }, { $push: { 'tasks.$.comments': comment } });
    const task = taskForCap;
    const notifBase = { fromUserId: userId, fromUsername: me.username || '', fromName: me.name, fromAvatarUrl: me.avatarUrl || '', status: 'pending' };
    const allNotifs = [];
    // Build set of project member IDs so @mentions only notify actual members
    const projectMemberIds = new Set([proj.ownerId, ...(proj.collaborators || []).map(c => c.userId).filter(Boolean)]);
    // @mention notifications (only for project members)
    let mentionedUserIds = new Set();
    if (safeMentions.length) {
      const mentionedUsers = await User.find({ username: { $in: safeMentions } }).select('id -_id').lean();
      mentionedUsers.filter(u => u.id !== userId && projectMemberIds.has(u.id)).forEach(u => {
        mentionedUserIds.add(u.id);
        allNotifs.push({ id: 'notif_' + uid(), ...notifBase, toUserId: u.id, type: 'mention',
          meta: { entityId: projectId, entityType: 'project', entityTitle: proj.title, taskId, taskTitle: task?.text?.slice(0, 60) || '', commentText: text.trim().slice(0, 100) } });
      });
    }
    // task_comment notifications for assignees not already @mentioned
    for (const aid of (task?.assignees || [])) {
      let toUserId;
      if (aid === 'me') { toUserId = proj.ownerId; }
      else { toUserId = proj.collaborators.find(c => c.id === aid)?.userId; }
      if (!toUserId || toUserId === userId || mentionedUserIds.has(toUserId)) continue;
      allNotifs.push({ id: 'notif_' + uid(), ...notifBase, toUserId, type: 'task_comment',
        meta: { entityId: projectId, entityType: 'project', entityTitle: proj.title, taskId, taskTitle: task?.text?.slice(0, 60) || '', commentText: text.trim().slice(0, 100) } });
    }
    if (allNotifs.length) await Notification.insertMany(allNotifs);
    emitProjectUpdate(req, projectId);
    res.json({ ok: true, comment });
    return;
  }

  // ── add_project_label ──
  if (action === 'add_project_label') {
    const { projectId, name, color } = req.body;
    if (!name?.trim()) { res.status(400).json({ error: 'Label name required' }); return; }
    if (color !== undefined && !isValidColor(color)) { res.status(400).json({ error: 'Invalid color format' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const labelId = 'lbl_' + uid();
    proj.labels.push({ id: labelId, name: name.trim().slice(0, 30), color: isValidColor(color) ? color : '#6366f1' });
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true, id: labelId });
    return;
  }

  // ── update_project_label ──
  if (action === 'update_project_label') {
    const { projectId, labelId, name, color } = req.body;
    if (!labelId) { res.status(400).json({ error: 'labelId required' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    const label = proj.labels.find(l => l.id === labelId);
    if (!label) { res.status(404).json({ error: 'Label not found' }); return; }
    if (name?.trim()) label.name = name.trim().slice(0, 30);
    if (color && isValidColor(color)) label.color = color;
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── delete_project_label ──
  if (action === 'delete_project_label') {
    const { projectId, labelId } = req.body;
    if (!labelId) { res.status(400).json({ error: 'labelId required' }); return; }
    const proj = await Project.findOne({ id: projectId, $or: [{ ownerId: userId }, { collaborators: { $elemMatch: { userId, role: 'editor' } } }] });
    if (!proj) { res.status(404).json({ error: 'Project not found' }); return; }
    proj.labels = proj.labels.filter(l => l.id !== labelId);
    proj.tasks.forEach(t => { if (t.badge === labelId) t.badge = ''; });
    await proj.save();
    emitProjectUpdate(req, projectId);
    res.json({ ok: true });
    return;
  }

  // ── reorder_spaces ──
  if (action === 'reorder_spaces') {
    const { order } = req.body;
    if (!Array.isArray(order) || order.length > 500) { res.status(400).json({ error: 'Invalid order' }); return; }
    const ops = order.map((id, index) => ({
      updateOne: { filter: { id, ownerId: userId }, update: { $set: { __orderRank: index } } }
    }));
    if (ops.length) await Space.collection.bulkWrite(ops);
    res.json({ ok: true });
    return;
  }

  res.status(404).json({ error: 'Unknown action' });
});

module.exports = { router, seedDefaultData };
