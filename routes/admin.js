const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const Project = require('../models/Project');
const Space = require('../models/Space');
const Feedback = require('../models/Feedback');
const requireAdmin = require('../middleware/requireAdmin');
const { deleteUserFiles } = require('../utils/storage');

async function auditLog(db, adminId, action, target, meta = {}) {
  try {
    await db.collection('audit_log').insertOne({ adminId, action, target, meta, timestamp: new Date() });
  } catch { /* never let audit failure break the response */ }
}

const router = express.Router();
router.use(requireAdmin);

// ── Overview stats ──
router.get('/stats', async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const [userCount, projectCount, feedbackCount, feedbackOpen] = await Promise.all([
      User.countDocuments(),
      Project.countDocuments(),
      Feedback.countDocuments(),
      Feedback.countDocuments({ status: 'open' }),
    ]);

    const taskAgg = await Project.aggregate([
      { $project: { taskCount: { $size: { $ifNull: ['$tasks', []] } } } },
      { $group: { _id: null, total: { $sum: '$taskCount' } } },
    ]);
    const taskCount = taskAgg[0]?.total || 0;

    const sessionCount = await db.collection('sessions').countDocuments({
      expires: { $gt: new Date() },
    });

    const dbStats = await db.stats();

    res.json({
      userCount,
      projectCount,
      taskCount,
      feedbackCount,
      feedbackOpen,
      sessionCount,
      dbSizeMB: (dbStats.dataSize / 1024 / 1024).toFixed(2),
    });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── List all users ──
router.get('/users', async (req, res) => {
  try {
    const users = await User.find({}).select('-passwordHash -__v').lean();
    const projectCounts = await Project.aggregate([
      { $group: { _id: '$ownerId', count: { $sum: 1 } } },
    ]);
    const pcMap = Object.fromEntries(projectCounts.map(p => [p._id, p.count]));

    res.json({
      users: users.map(u => ({ ...u, projectCount: pcMap[u.id] || 0 })),
    });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Grant superadmin by email ──
router.post('/users/grant', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await User.findOneAndUpdate(
      { email: email.toLowerCase().trim() },
      { role: 'superadmin' },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'No user with that email' });
    const db = mongoose.connection.db;
    await auditLog(db, req.session.userId, 'grant_admin', user.id, { email: user.email });
    res.json({ ok: true, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Revoke superadmin ──
router.post('/users/:id/revoke', async (req, res) => {
  try {
    if (req.params.id === req.session.userId) {
      return res.status(400).json({ error: 'Cannot revoke your own superadmin role' });
    }
    const user = await User.findOneAndUpdate({ id: req.params.id }, { role: 'user' }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    // Force-expire all sessions for this user so the revocation takes effect immediately
    const db = mongoose.connection.db;
    const allSessions = await db.collection('sessions').find({}).toArray();
    const toDelete = allSessions
      .filter(s => { try { return JSON.parse(s.session).userId === req.params.id; } catch { return false; } })
      .map(s => s._id);
    if (toDelete.length) await db.collection('sessions').deleteMany({ _id: { $in: toDelete } });
    await auditLog(db, req.session.userId, 'revoke_admin', req.params.id, { email: user.email });
    res.json({ ok: true });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Delete user + all their data ──
router.delete('/users/:id', async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.session.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    const targetUser = await User.findOne({ id: targetId }).select('email -_id').lean();
    // Delete stored files before removing documents
    const userProjects = await Project.find({ ownerId: targetId }).select('files tasks').lean();
    await deleteUserFiles(targetId, userProjects);
    await Promise.all([
      User.deleteOne({ id: targetId }),
      Project.deleteMany({ ownerId: targetId }),
      Space.deleteMany({ ownerId: targetId }),
      Feedback.deleteMany({ userId: targetId }),
    ]);
    // Force-expire all sessions for this user
    const db = mongoose.connection.db;
    const allSessions = await db.collection('sessions').find({}).toArray();
    const sessionIds = allSessions
      .filter(s => { try { return JSON.parse(s.session).userId === targetId; } catch { return false; } })
      .map(s => s._id);
    if (sessionIds.length) {
      await db.collection('sessions').deleteMany({ _id: { $in: sessionIds } });
    }
    await auditLog(db, req.session.userId, 'delete_user', targetId, { email: targetUser?.email });
    res.json({ ok: true });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Active sessions ──
router.get('/sessions', async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const raw = await db.collection('sessions').find({ expires: { $gt: new Date() } }).toArray();

    const userIds = raw.map(s => {
      try { return JSON.parse(s.session).userId; } catch { return null; }
    }).filter(Boolean);

    const users = await User.find({ id: { $in: userIds } }).select('id email name -_id').lean();
    const userMap = Object.fromEntries(users.map(u => [u.id, u]));

    const sessions = raw.map(s => {
      let userId = null;
      try { userId = JSON.parse(s.session).userId; } catch {}
      if (!userId) return null;
      const u = userMap[userId];
      return {
        sessionId: s._id.toString(),
        userId,
        userName: u?.name || 'Unknown',
        userEmail: u?.email || 'Unknown',
        expires: s.expires,
        isSelf: userId === req.session.userId,
      };
    }).filter(Boolean);

    res.json({ sessions });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Force-logout a session ──
router.delete('/sessions/:id', async (req, res) => {
  try {
    const db = mongoose.connection.db;
    // connect-mongo v6 stores sessions with a string _id (the session ID)
    const result = await db.collection('sessions').deleteOne({ _id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Session not found or already expired' });
    await auditLog(db, req.session.userId, 'force_logout_session', req.params.id, {});
    res.json({ ok: true });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── All feedback (admin view) ──
router.get('/feedback', async (req, res) => {
  try {
    const items = await Feedback.find({}).sort({ createdAt: -1 }).lean();
    res.json({
      items: items.map(({ _id, __v, upvotes, ...rest }) => ({
        ...rest,
        upvoteCount: (upvotes || []).length,
      })),
    });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Delete feedback item ──
router.delete('/feedback/:id', async (req, res) => {
  try {
    await Feedback.deleteOne({ id: req.params.id });
    const db = mongoose.connection.db;
    await auditLog(db, req.session.userId, 'delete_feedback', req.params.id, {});
    res.json({ ok: true });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── System info ──
router.get('/system', async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const collectionNames = await db.listCollections().toArray();

    const collStats = await Promise.all(
      collectionNames.map(async c => {
        try {
          const stats = await db.collection(c.name).stats();
          return { name: c.name, count: stats.count, sizeMB: (stats.size / 1024 / 1024).toFixed(3) };
        } catch {
          return { name: c.name, count: '?', sizeMB: '?' };
        }
      })
    );

    const envHealth = {
      MONGODB_URI:         !!process.env.MONGODB_URI,
      SESSION_SECRET:      !!process.env.SESSION_SECRET,
      ADMIN_EMAILS:        !!process.env.ADMIN_EMAILS,
      R2_ACCOUNT_ID:       !!process.env.R2_ACCOUNT_ID,
      R2_ACCESS_KEY_ID:    !!process.env.R2_ACCESS_KEY_ID,
      R2_SECRET_ACCESS_KEY:!!process.env.R2_SECRET_ACCESS_KEY,
      R2_BUCKET_NAME:      !!process.env.R2_BUCKET_NAME,
      RESEND_API_KEY:      !!process.env.RESEND_API_KEY,
      APP_URL:             !!process.env.APP_URL,
    };

    res.json({
      collections: collStats,
      envHealth,
      nodeVersion: process.version,
      uptime: Math.floor(process.uptime()),
      nodeEnv: process.env.NODE_ENV || 'development',
    });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Analytics (charts + distributions) ──
function fillDays(raw, days) {
  const map = Object.fromEntries(raw.map(d => [d._id, d.count]));
  const result = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
    result.push({ date: d.toISOString().split('T')[0], count: map[d.toISOString().split('T')[0]] || 0 });
  }
  return result;
}

router.get('/analytics', async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const nowStr = new Date().toISOString();
    const db = mongoose.connection.db;

    const [
      userGrowthRaw,
      feedbackTrendRaw,
      taskAgg,
      projectCountsAgg,
      taskCountsAgg,
      fileAgg,
      spaceProjectAgg,
      recentSignups,
      sessionCount,
      dbStats,
    ] = await Promise.all([
      User.aggregate([
        { $match: { createdAt: { $gte: thirtyDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]),
      Feedback.aggregate([
        { $match: { createdAt: { $gte: thirtyDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]),
      Project.aggregate([
        { $unwind: { path: '$tasks', preserveNullAndEmptyArrays: false } },
        { $group: {
          _id: null,
          total:     { $sum: 1 },
          done:      { $sum: { $cond: ['$tasks.done', 1, 0] } },
          urgent:    { $sum: { $cond: [{ $eq: ['$tasks.priority', 'urgent'] }, 1, 0] } },
          important: { $sum: { $cond: [{ $eq: ['$tasks.priority', 'important'] }, 1, 0] } },
          later:     { $sum: { $cond: [{ $eq: ['$tasks.priority', 'later'] }, 1, 0] } },
          overdue:   { $sum: { $cond: [{ $and: [
            { $eq: ['$tasks.done', false] },
            { $gt: ['$tasks.deadline', ''] },
            { $lt: ['$tasks.deadline', nowStr] },
          ]}, 1, 0] } },
        }},
      ]),
      Project.aggregate([
        { $group: { _id: '$ownerId', projectCount: { $sum: 1 } } },
        { $sort: { projectCount: -1 } },
        { $limit: 10 },
      ]),
      Project.aggregate([
        { $project: { ownerId: 1, taskCount: { $size: { $ifNull: ['$tasks', []] } } } },
        { $group: { _id: '$ownerId', taskCount: { $sum: '$taskCount' } } },
      ]),
      Project.aggregate([
        { $project: { fileCount: { $size: { $ifNull: ['$files', []] } } } },
        { $group: { _id: null, total: { $sum: '$fileCount' } } },
      ]),
      Project.aggregate([
        { $group: { _id: '$spaceId', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      User.find({}).sort({ createdAt: -1 }).limit(6).select('id name email role createdAt -_id').lean(),
      db.collection('sessions').countDocuments({ expires: { $gt: new Date() } }),
      db.stats(),
    ]);

    // Top users — join project + task counts
    const taskCountMap = Object.fromEntries(taskCountsAgg.map(t => [t._id, t.taskCount]));
    const topUserIds   = projectCountsAgg.map(p => p._id);
    const topUserDocs  = await User.find({ id: { $in: topUserIds } }).select('id name email -_id').lean();
    const topUserMap   = Object.fromEntries(topUserDocs.map(u => [u.id, u]));
    const topUsers     = projectCountsAgg
      .map(p => ({ ...topUserMap[p._id], projectCount: p.projectCount, taskCount: taskCountMap[p._id] || 0 }))
      .filter(u => u.name);

    // Space distribution — join space titles
    const spaceIds  = spaceProjectAgg.map(s => s._id).filter(Boolean);
    const spaceDocs = await Space.find({ id: { $in: spaceIds } }).select('id title -_id').lean();
    const spaceMap  = Object.fromEntries(spaceDocs.map(s => [s.id, s]));
    const spaceDistribution = spaceProjectAgg.map(s => ({
      title: spaceMap[s._id]?.title || 'Unnamed',
      count: s.count,
    }));

    // Overall counts
    const [userCount, projectCount, archivedCount, feedbackOpen, feedbackTotal] = await Promise.all([
      User.countDocuments(),
      Project.countDocuments(),
      Project.countDocuments({ archived: true }),
      Feedback.countDocuments({ status: 'open' }),
      Feedback.countDocuments(),
    ]);

    const ts = taskAgg[0] || { total: 0, done: 0, urgent: 0, important: 0, later: 0, overdue: 0 };

    res.json({
      counts: {
        users:           userCount,
        projects:        projectCount,
        archivedProjects:archivedCount,
        tasks:           ts.total,
        tasksDone:       ts.done,
        tasksOpen:       ts.total - ts.done,
        tasksOverdue:    ts.overdue,
        files:           fileAgg[0]?.total || 0,
        feedbackOpen,
        feedbackTotal,
        activeSessions:  sessionCount,
        dbSizeMB:        (dbStats.dataSize / 1024 / 1024).toFixed(2),
      },
      taskPriority: {
        urgent:    ts.urgent,
        important: ts.important,
        later:     ts.later,
        none:      Math.max(0, ts.total - ts.urgent - ts.important - ts.later),
      },
      completionRate: ts.total ? Math.round(ts.done / ts.total * 100) : 0,
      userGrowth:      fillDays(userGrowthRaw, 30),
      feedbackTrend:   fillDays(feedbackTrendRaw, 30),
      topUsers,
      spaceDistribution,
      recentSignups,
    });
  } catch (err) {
    console.error('[admin]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
