# Vault of Troy — Simply Secure

Responsive React + Vite frontend for the Secure Document Vault and File-Sharing Service. It uses the existing backend API at `http://localhost:4000` by default and does not substitute mock data for API responses.

## Requirements
- Node.js 20+
- The Aegis Vault backend from the companion backend package

## Run
```bash
cp .env.example .env
npm install
npm run dev
```
Open the URL printed by Vite (usually `http://localhost:5173`).

## Production build
```bash
npm run build
npm run preview
```

## Backend setup
Start the backend on port 4000 first. The frontend expects the session-authenticated endpoints documented in the backend README. Configure `VITE_API_BASE_URL` if the backend is hosted elsewhere. The backend must allow the frontend origin with credentials if frontend and backend are on different origins; same-origin reverse proxy is recommended.

## API integrations
- `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`
- `/api/dashboard`, `/api/documents`, `/api/shares`, `/api/audit`, `/api/confidentiality-map`
- `/api/panic`, `/api/documents/:id`, `/api/shares/:id`
- `/s/:token`, `/s/:token/otp/request`, `/s/:token/otp/verify`, `/s/:token/download`

## Honest capability notes
- Frontend reflects server status. Uploads remain quarantined unless backend malware scanning approves them.
- The backend currently has no PDF preview endpoint, no share-passcode support, and no progress-stream endpoint. The UI does not claim those capabilities exist.
- Share link URL/token is shown immediately after creation because backend returns it once; the token is not recoverable from the database.
- For cross-origin development, configure backend CORS and cookie settings appropriately or use a same-origin proxy.
