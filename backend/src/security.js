const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs/promises');
const config = require('./config');

const uuid = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const token = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const hashIp = ip => sha256(`${process.env.IP_HASH_SALT || 'dev-ip-salt-change-me'}:${ip || 'unknown'}`);
const safeName = name => path.basename(String(name || 'document')).replace(/[^\w.\- ()]/g, '_').slice(0, 180) || 'document';
const allowedMime = new Set([
  'application/pdf', 'image/png', 'image/jpeg', 'image/webp',
  'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);
async function detectAndValidate(filePath, originalName) {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(filePath);
  const ext = path.extname(originalName).toLowerCase();
  const extMap = {
    '.pdf':'application/pdf', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
    '.webp':'image/webp', '.txt':'text/plain', '.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  };
  // Text and DOCX need explicit content handling because file-type may not identify them reliably.
  if (ext === '.txt') {
    const b = await fs.readFile(filePath);
    if (b.includes(0)) throw Object.assign(new Error('Binary content is not accepted as text'), { status: 415 });
    return 'text/plain';
  }
  if (ext === '.docx') {
    const b = await fs.readFile(filePath);
    if (b.length < 4 || b.readUInt32LE(0) !== 0x04034b50) throw Object.assign(new Error('Invalid DOCX container'), { status: 415 });
    return extMap[ext];
  }
  if (!detected || detected.mime !== extMap[ext] || !allowedMime.has(detected.mime)) {
    throw Object.assign(new Error('File extension and detected content do not match or type is unsupported'), { status: 415 });
  }
  return detected.mime;
}
async function scanFile(filePath) {
  if (!config.SCAN_UPLOADS) return { clean: false, reason: 'scanner_disabled' };
  if (!config.CLAMSCAN_PATH) return { clean: false, reason: 'scanner_not_configured' };
  const { execFile } = require('node:child_process');
  const { promisify } = require('node:util');
  try {
    await promisify(execFile)(config.CLAMSCAN_PATH, ['--no-summary', filePath], { timeout: 15000 });
    return { clean: true, reason: 'clean' };
  } catch (err) {
    if (err.code === 1) return { clean: false, reason: 'malware_detected' };
    return { clean: false, reason: 'scanner_error' };
  }
}
module.exports = { uuid, now, token, sha256, hashIp, safeName, detectAndValidate, scanFile };
