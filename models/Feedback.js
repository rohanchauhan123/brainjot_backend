const mongoose = require('mongoose');
const feedbackSchema = new mongoose.Schema({
  id:       { type: String, required: true, unique: true },
  userId:   { type: String, required: true },
  userName: { type: String, required: true },
  message:  { type: String, required: true, maxlength: 500 },
  type:     { type: String, enum: ['bug', 'idea', 'general'], default: 'general' },
  status:   { type: String, enum: ['open', 'fixed'], default: 'open' },
  upvotes:  [{ type: String }],
  createdAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('Feedback', feedbackSchema);
