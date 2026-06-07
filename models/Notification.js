const mongoose = require('mongoose');

const notifSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  toUserId:    { type: String, required: true, index: true },
  fromUserId:    String,
  fromUsername:  String,
  fromName:      String,
  fromAvatarUrl: String,
  type: { type: String, enum: ['collab_invite', 'mention', 'comment', 'task_assigned', 'invite_response', 'task_comment'], required: true },
  meta: {
    entityId:    String,
    entityType:  String,
    entityTitle: String,
    role:        String,
    taskId:      String,
    taskTitle:   String,
    commentText: String,
    accepted:    Boolean,
  },
  status: { type: String, enum: ['pending', 'accepted', 'denied', 'read'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Notification', notifSchema);
