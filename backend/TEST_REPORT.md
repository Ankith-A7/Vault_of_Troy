# Test report

Automated tests are included in `test/security.test.js` and use Node's test runner + Supertest.

Run:
```bash
npm install
npm test
```

Coverage target list:
- authentication required, registration validation and failed login
- unauthorized / non-owner direct-object access
- unsupported upload types and oversized uploads
- revoked and expired links
- download-limit enforcement and panic revocation
- dashboard and audit API access

Important: this report describes the test suite, not a claim that it passed in this environment. See the final run output and update this file after running tests on the target machine.
