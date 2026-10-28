# Vault of Troy — Simply Secure | Implementation status

## Phase 0 — Inspect and preserve
- [x] Checked available project archives. The prior `my-full-stack-project.zip` is a static HTML/CSS site unrelated to this vault; no existing Vault of Troy frontend source was present.
- [x] Created a separate React + Vite frontend rather than overwrite the existing site.

## Phase 1 — Shell and identity
- [x] Renamed product branding to Vault of Troy — Simply Secure.
- [x] Responsive midnight navy / mint / cloud white / amber visual system.
- [x] Login and registration wired to backend session endpoints.

## Phase 2 — Backend-connected workspace
- [x] Dashboard counts, document list, share list, audit events and confidentiality map load from APIs.
- [x] Search and document status filters.
- [x] Upload flow, file selection/drag-drop, server-side validation feedback, quarantine status.
- [x] Share policy builder, permission profiles, expiry, download limits and OTP recipient configuration.
- [x] Revoke links, Panic Button confirmation, delete confirmation, audit timeline and map.

## Phase 3 — Recipient and safety flows
- [x] Recipient share page, OTP request/verify, expiry and download policy display.
- [x] Safety status and privacy-preview warning.
- [ ] PDF in-browser preview and passcode policy are not implemented by the provided backend API; not represented as working features.

## Phase 4 — Verification
- [ ] Install dependencies and run `npm run build` on target machine.
- [ ] Test against a running backend with configured clean malware scanning and SMTP.
- [ ] Existing backend currently does not expose an approved-PDF preview endpoint. Share passcodes are not supported by the backend.

## Phase 5 — Frontend-only quarantine recovery
- [x] Added a per-document “Re-scan quarantined file” action for quarantined documents.
- [x] The action uploads a user-selected copy through the existing upload API, compares the returned SHA-256 digest with the original, and never directly changes a status in the browser.
- [x] If the backend scanner approves an identical copy, the frontend deletes the original quarantined record and refreshes the vault; if it remains quarantined/rejected, the UI explains the result and preserves the original record.
- [!] This is a frontend-only workaround, not a manual approval API. It requires the existing backend scanner to be correctly configured and may be blocked by quota because both copies temporarily count against the user's quota. No unsafe database/status bypass was added.
- [ ] Build/runtime verification still requires dependency installation on the target machine.
