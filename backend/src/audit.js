const db = require('./db');
const { uuid, now, hashIp } = require('./security');
function audit({ actorId = null, documentId = null, shareId = null, event, outcome = 'success', ip = '', details = {} }) {
  db.prepare(`INSERT INTO audit_events(id,actor_id,document_id,share_id,event_type,outcome,ip_hash,details_json,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(uuid(), actorId, documentId, shareId, event, outcome, hashIp(ip), JSON.stringify(details), now());
}
module.exports = { audit };
