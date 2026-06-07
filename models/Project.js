const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  id: String,
  name: String,
  file: String,
  url: String,
  type: String,
  size: Number,
  uploaded: String,
}, { _id: false });

const labelSchema = new mongoose.Schema({
  id: String,
  name: String,
  color: String,
}, { _id: false });

const collaboratorSchema = new mongoose.Schema({
  id: String,
  userId: String,
  name: String,
  username: String,
  email: String,
  role: String,
  status: String,
  avatarUrl: String,
}, { _id: false });

const taskSchema = new mongoose.Schema({
  id: String,
  text: String,
  done: Boolean,
  badge: { type: String, default: '' },
  notes: { type: String, default: '' },
  richNotes: { type: String, default: '' },
  files: [fileSchema],
  deadline: { type: String, default: '' },
  assignee: { type: String, default: '' }, // kept for backward compatibility
  assignees: [String],
  priority: { type: String, default: '' },
  comments: [{
    id: String,
    userId: String,
    username: String,
    name: String,
    avatarUrl: String,
    text: String,
    mentions: [String],
    createdAt: { type: Date, default: Date.now },
  }],
  createdAt: { type: Date, default: Date.now },
  finishedAt: { type: Date, default: null },
}, { _id: false });

const projectSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  color: { type: String, default: '#888785' },
  tag: { type: String, default: 'Project' },
  tasks: [taskSchema],
  notes: { type: String, default: '' },
  richNotes: { type: String, default: '' },
  files: [fileSchema],
  collaborators: [collaboratorSchema],
  labels: [labelSchema],
  archived: { type: Boolean, default: false },
  spaceId: { type: String, default: '' },
  ownerId: { type: String, index: true },
  __orderRank: { type: Number, default: 0 },
  inviteToken: { type: String, default: '' },
  inviteLinkRole: { type: String, default: 'editor' },
  inviteTokenExpiry: { type: Date, default: null },
});

module.exports = mongoose.model('Project', projectSchema);
