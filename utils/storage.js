const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { S3Client, DeleteObjectCommand, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { SignatureV4 } = require('@smithy/signature-v4');
const logger = require('./logger');

const UPLOADS_DIR = path.resolve(__dirname, '..', process.env.UPLOADS_DIR || 'uploads');

const R2_ACCOUNT_ID        = (process.env.R2_ACCOUNT_ID        || '').trim();
const R2_ACCESS_KEY_ID     = (process.env.R2_ACCESS_KEY_ID     || '').trim();
const R2_SECRET_ACCESS_KEY = (process.env.R2_SECRET_ACCESS_KEY || '').trim();
const R2_BUCKET_NAME       = (process.env.R2_BUCKET_NAME       || '').trim();
const R2_PUBLIC_URL        = (process.env.R2_PUBLIC_URL        || '').trim();

const useR2 = !!(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET_NAME);

// S3Client is used only for delete operations.
// Uploads use browser-direct presigned URLs (see getPresignedPutUrl).
const s3 = useR2 ? new S3Client({
  region: 'auto',
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY },
  forcePathStyle: true,
}) : null;

if (useR2) {
  logger.info({
    host: `${R2_ACCOUNT_ID.slice(0, 6)}***.r2.cloudflarestorage.com`,
    bucket: R2_BUCKET_NAME,
    mode: 'presigned-url (browser-direct)',
  }, '[storage] R2 configured');
}

// SHA-256 backed by Node.js built-in crypto — required by @smithy/signature-v4
class NodeSha256 {
  constructor() { this._h = crypto.createHash('sha256'); }
  update(data, enc) {
    if (typeof data === 'string') this._h.update(data, enc || 'utf8');
    else this._h.update(data);
  }
  digest() { return Promise.resolve(this._h.digest()); }
}

// Generate a presigned PUT URL for browser-direct upload.
// This is pure local computation — no network call is made.
// The browser then PUT-s the file directly to R2, bypassing the server's
// broken TLS path to r2.cloudflarestorage.com entirely.
async function getPresignedPutUrl(key, mimeType, expiresIn = 300) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  const urlPath = `/${R2_BUCKET_NAME}/${encodedKey}`;

  const signer = new SignatureV4({
    service: 's3',
    region: 'auto',
    credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY },
    sha256: NodeSha256,
  });

  const presigned = await signer.presign(
    {
      method: 'PUT',
      hostname: host,
      protocol: 'https:',
      path: urlPath,
      headers: { host },
    },
    {
      expiresIn,
      // Don't sign content-type/content-length so the browser can set them freely
      unsignableHeaders: new Set(['content-type', 'content-length']),
    },
  );

  const qs = Object.entries(presigned.query || {})
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(Array.isArray(v) ? v[0] : v)}`)
    .join('&');

  const url = `https://${host}${urlPath}?${qs}`;
  logger.info({ key, expiresIn }, '[storage] presigned PUT URL generated');
  return url;
}

async function deleteStoredFile(fileRecord) {
  if (useR2) {
    try {
      await s3.send(new DeleteObjectCommand({ Bucket: R2_BUCKET_NAME, Key: fileRecord.file }));
    } catch (err) {
      const code = err?.name || err?.Code;
      if (code !== 'NoSuchKey' && code !== 'NotFound') {
        logger.error({ key: fileRecord.file, code, message: err.message }, '[storage] R2 delete failed');
      }
    }
  } else {
    const fp = path.join(UPLOADS_DIR, fileRecord.file);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
}

async function deleteUserFiles(userId, projects = []) {
  const keys = [];
  for (const proj of projects) {
    for (const f of proj.files || []) keys.push(f.file);
    for (const t of proj.tasks || []) {
      for (const f of t.files || []) keys.push(f.file);
    }
  }
  keys.push(`avatars/${userId}.jpg`);

  if (useR2) {
    const chunks = [];
    for (let i = 0; i < keys.length; i += 1000) chunks.push(keys.slice(i, i + 1000));
    for (const chunk of chunks) {
      try {
        await s3.send(new DeleteObjectsCommand({
          Bucket: R2_BUCKET_NAME,
          Delete: { Objects: chunk.map(Key => ({ Key })), Quiet: true },
        }));
      } catch (err) {
        const code = err?.name || err?.Code;
        if (code !== 'NoSuchKey' && code !== 'NotFound') {
          logger.error({ keyCount: chunk.length, code, message: err.message }, '[storage] R2 bulk delete failed');
        }
      }
    }
  } else {
    for (const key of keys) {
      const fp = path.join(UPLOADS_DIR, key);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
  }
}

function filePublicUrl(key) {
  return useR2
    ? `${R2_PUBLIC_URL}/${key}`
    : `uploads/${key}`;
}

module.exports = { UPLOADS_DIR, useR2, s3, getPresignedPutUrl, deleteStoredFile, deleteUserFiles, filePublicUrl };
