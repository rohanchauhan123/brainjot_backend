const mongoose = require('mongoose');

const invitationSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  email: { type: String, required: true, lowercase: true, trim: true },
  entityId: { type: String, required: true },
  entityType: { type: String, enum: ['project', 'space'], required: true },
  role: { type: String, enum: ['editor', 'viewer'], default: 'editor' },
  inviterName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 604800 } // expires in 7 days (604,800 seconds)
});

module.exports = mongoose.model('Invitation', invitationSchema);
