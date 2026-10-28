# Vault of Troy — Simply Secure backend

Security-oriented Express + SQLite backend for the RVCE PS2 Secure Document Vault project. It is intentionally separate from the frontend so the existing UI can be preserved and connected through `/api` endpoints.

## Requirements
- Node.js 20+
- npm
- Optional for full recipient OTP delivery: SMTP account
- Optional for malware scanning: ClamAV `clamscan` binary

## Install and run
```bash
cp .env.example .env
# Edit .env: set a unique SESSION_SECRET (32+ chars) and production settings.
npm install
npm run db:init
npm test
npm start
```
API health: `GET http://localhost:4000/api/health`.

## Core API
- `POST /api/auth/register` `{email,password}` (password 12+ chars)
- `POST /api/auth/login` `{email,password}`
- `POST /api/auth/logout`, `GET /api/auth/me`
- `POST /api/documents` multipart field `file`; `GET /api/documents`; `GET /api/documents/:id`; `DELETE /api/documents/:id`
- `POST /api/shares` `{documentId,expiresInHours,downloadLimit,profile,recipientEmail?}`
- `GET /api/shares`, `DELETE /api/shares/:id`, `POST /api/panic`
- `GET /s/:token`, `GET /s/:token/download`
- `POST /s/:token/otp/request` `{email}`, `POST /s/:token/otp/verify` `{email,code}`
- `GET /api/dashboard`, `GET /api/audit?limit=50`, `GET /api/confidentiality-map`

## File safety model
Supported extensions: PDF, PNG, JPEG, WebP, TXT, DOCX. File bytes are stored outside public web roots with generated names. A file is downloadable only when status is `approved`. Configure `CLAMSCAN_PATH` to an installed ClamAV executable. Without a configured scanner, uploads remain quarantined by design. Do not manually mark unscanned files approved in production.

## Security notes
- Cookies are HttpOnly/SameSite=Lax; production requires HTTPS for Secure cookies.
- Session secret must be unique and private.
- OTP email requires SMTP in production. In development, codes are logged to the server console only.
- Deploy behind HTTPS; enable `TRUST_PROXY=true` only behind a trusted reverse proxy.
- Add CSRF protection if browser clients use cross-site cookies; current same-site cookie policy is intended for same-origin frontend deployments.
- This is a strong project baseline, not a third-party security audit. Review before real confidential documents or public production deployment.
