# Vault of Troy — Simply Secure

Full-stack document vault project in one folder. `backend/` is the Express + SQLite API; `frontend/` is the React + Vite UI.

## Requirements
- Node.js 20 or newer (includes npm)
- macOS / Windows / Linux

## First-time setup (from this folder)
1. Open this folder in VS Code.
2. In Terminal, confirm `node -v` is 20 or newer and `npm -v` prints a version.
3. Create local environment files:

   macOS/Linux:
   ```bash
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   ```

   Windows PowerShell:
   ```powershell
   Copy-Item backend/.env.example backend/.env
   Copy-Item frontend/.env.example frontend/.env
   ```

4. Install all dependencies from the root (do not run npm install separately in the subfolders):
   ```bash
   npm install
   ```
5. Initialize the SQLite database and storage folders:
   ```bash
   npm run setup
   ```
6. Start backend and frontend together:
   ```bash
   npm run dev
   ```
7. Open **http://localhost:5173**. The API health endpoint is **http://localhost:4000/api/health**. Keep the terminal open while using the app. Stop both services with Ctrl+C.

## If `npm run setup` or `npm run dev` fails
- Run `node -v`; install Node.js 20+ from https://nodejs.org/ if the command is missing or too old.
- Make sure you are in the root `vault-of-troy-simply-secure` folder (the one containing this README and root `package.json`).
- If port 4000 or 5173 is already in use, stop the other process or change `PORT` in `backend/.env` and Vite port config as needed.
- If `.env` files already exist, do not overwrite them blindly; check `backend/.env` has a `SESSION_SECRET` of at least 32 characters.
- On macOS/Linux you can generate one with `openssl rand -hex 32`. Put the output in `backend/.env` as `SESSION_SECRET=...`.
- `SCAN_UPLOADS=true` without `CLAMSCAN_PATH` keeps uploads quarantined by design. Install ClamAV and configure `CLAMSCAN_PATH` if you want clean uploads to be approved. Do not treat unscanned files as safe.
- Recipient OTP is logged only in development when SMTP is not configured. Configure SMTP before production use.

## Verify
In another terminal at the project root:
```bash
npm run check
npm test
```
`npm run check` performs backend syntax checks and a frontend production build. Tests need dependencies installed.

## Important notes
- This is a security-minded academic project starter, not a security audit or production certification. Configure HTTPS, a strong secret, SMTP, malware scanning, backups and deployment-specific CORS before real sensitive documents are used.
- SQLite and storage paths are under `backend/`; keep the whole backend folder intact.
- The frontend calls the real backend APIs; no mock documents are seeded. Register a new account in the UI to begin.


### Owner approval PIN
New registrations must choose a six-digit approval PIN. Existing accounts can set one from the sidebar's **Set / change approval PIN** action after re-entering their password. In My Vault, use the shield-check icon on a quarantined file and enter the PIN to authorize release. This is a user-authorized override, not a malware scan: the UI requires risk acknowledgement and the event is recorded in the audit log. Do not approve files you do not trust.
