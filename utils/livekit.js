const LIVEKIT_API_KEY    = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL        = process.env.LIVEKIT_URL;

const livekitEnabled = !!(LIVEKIT_API_KEY && LIVEKIT_API_SECRET && LIVEKIT_URL);

// In-memory call state: projectId → { hostUserId, hostName, callType, roomName, startedAt }
// Lives in this singleton module so both the HTTP router and socket.io handler share it.
const activeCalls = new Map();

async function generateToken(userId, userName, roomName) {
  const { AccessToken } = require('livekit-server-sdk');
  const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity: userId,
    name: userName,
    ttl: '2h',
  });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  return await at.toJwt();
}

module.exports = { livekitEnabled, activeCalls, generateToken, LIVEKIT_URL };
