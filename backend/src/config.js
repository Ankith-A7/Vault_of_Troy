const path = require('node:path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const { z } = require('zod');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  BASE_URL: z.string().url().default('http://localhost:4000'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters').default('development-only-change-this-secret-32-chars'),
  DATABASE_PATH: z.string().default('./data/aegis.sqlite'),
  STORAGE_DIR: z.string().default('./storage'),
  MAX_FILE_BYTES: z.coerce.number().int().positive().default(10 * 1024 * 1024),
  USER_QUOTA_BYTES: z.coerce.number().int().positive().default(100 * 1024 * 1024),
  MAX_ACTIVE_SHARES: z.coerce.number().int().positive().default(50),
  DEFAULT_SHARE_HOURS: z.coerce.number().int().positive().default(24),
  MAX_SHARE_HOURS: z.coerce.number().int().positive().default(720),
  DEFAULT_DOWNLOAD_LIMIT: z.coerce.number().int().positive().default(5),
  OTP_TTL_MINUTES: z.coerce.number().int().positive().default(10),
  OTP_RESEND_SECONDS: z.coerce.number().int().nonnegative().default(60),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),
  BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(15).default(12),
  SMTP_HOST: z.string().optional().default(''),
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_SECURE: z.enum(['true','false']).default('false').transform(v => v === 'true'),
  SMTP_USER: z.string().optional().default(''),
  SMTP_PASS: z.string().optional().default(''),
  MAIL_FROM: z.string().default('Aegis Vault <no-reply@example.invalid>'),
  CLAMSCAN_PATH: z.string().optional().default(''),
  SCAN_UPLOADS: z.enum(['true','false']).default('true').transform(v => v === 'true'),
  TRUST_PROXY: z.enum(['true','false']).default('false').transform(v => v === 'true')
});
const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}
const env = parsed.data;
if (env.NODE_ENV === 'production' && env.SESSION_SECRET === 'development-only-change-this-secret-32-chars') {
  console.error('SESSION_SECRET must be explicitly configured in production.');
  process.exit(1);
}
const root = path.resolve(__dirname, '..');
module.exports = {
  ...env,
  DB_FILE: path.resolve(root, env.DATABASE_PATH),
  STORAGE_ROOT: path.resolve(root, env.STORAGE_DIR),
  QUARANTINE_DIR: path.resolve(root, env.STORAGE_DIR, 'quarantine'),
  APPROVED_DIR: path.resolve(root, env.STORAGE_DIR, 'approved'),
  IS_PRODUCTION: env.NODE_ENV === 'production'
};
