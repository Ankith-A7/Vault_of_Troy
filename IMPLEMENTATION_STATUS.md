# Vault of Troy — Simply Secure | Combined project status

- [x] Packaged backend and frontend together under one root folder.
- [x] Root npm workspace scripts for one install, database initialization, concurrent development, build and tests.
- [x] Added backend dotenv loading from `backend/.env`.
- [x] Added credentialed CORS for local Vite origins (`localhost:5173` and `127.0.0.1:5173`).
- [x] Updated API health identity and OTP development log branding.
- [x] Frontend API base URL defaults to `http://localhost:4000`.
- [x] JavaScript syntax checks pass for backend app/config/server.
- [ ] Full npm install and frontend build could not be verified in this environment because dependency installation timed out. Run `npm install` and `npm run check` locally.
- [ ] Configure ClamAV and SMTP before using for real sensitive files or production deployment.


## Approval PIN update (2026-10-28)
- Registration now requires a user-selected six-digit approval PIN; the backend stores only a bcrypt hash.
- Existing signed-in users can set/change their PIN from the sidebar after re-entering their account password.
- Quarantined documents have a PIN-authorized owner release action; it is rate-limited, ownership-checked, and audited.
- Security note: owner release does not prove a file is malware-free and deliberately bypasses scanner approval; the UI requires explicit risk acknowledgement. Use only for files you trust.
- Validation performed: backend files pass `node --check`. Full dependency install/build and end-to-end tests have not been run in this environment.
