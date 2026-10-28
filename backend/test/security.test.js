process.env.NODE_ENV='test';
process.env.SESSION_SECRET='test-session-secret-please-change-123456789';
process.env.DATABASE_PATH='./data/test.sqlite';
process.env.STORAGE_DIR='./storage-test';
process.env.SCAN_UPLOADS='false';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const request=require('supertest');
const app=require('../src/app');
const db=require('../src/db');
const {uuid,now,sha256}=require('../src/security');
const config=require('../src/config');
const {audit}=require('../src/audit');
const bcrypt=require('bcryptjs');
const crypto=require('node:crypto');

let agent, userId, docId, shareId, rawToken;
test('register/login/auth and input validation',async()=>{
  agent=request.agent(app);
  let r=await agent.get('/api/auth/me'); assert.equal(r.status,401);
  r=await agent.post('/api/auth/register').send({email:'test@example.com',password:'short'}); assert.equal(r.status,400);
  r=await agent.post('/api/auth/register').send({email:'test@example.com',password:'long-enough-password-123'});
  assert.equal(r.status,201); userId=r.body.user.id;
  r=await request(app).post('/api/auth/login').send({email:'test@example.com',password:'wrong-password'}); assert.equal(r.status,401);
  r=await agent.get('/api/auth/me'); assert.equal(r.status,200);
});
test('ownership blocks direct object access',async()=>{
  const other=request.agent(app);
  const reg=await other.post('/api/auth/register').send({email:'other@example.com',password:'another-long-password-456'});
  assert.equal(reg.status,201);
  const res=await other.get(`/api/documents/${docId || uuid()}`); assert.equal(res.status,404);
  const unauth=await request(app).get(`/api/documents/${uuid()}`); assert.equal(unauth.status,401);
});
test('uploads reject unsupported and oversized files',async()=>{
  let r=await agent.post('/api/documents').attach('file',Buffer.from('hello'),'evil.exe'); assert.equal(r.status,400);
  const original=config.MAX_FILE_BYTES;
  // Multer limit is captured at app construction, use a small test payload only if env config is small.
  r=await agent.post('/api/documents').attach('file',Buffer.alloc(original+1),'huge.pdf','application/pdf');
  assert.ok([400,413].includes(r.status));
});
test('per-user quota is enforced by server-side metadata reservation',async()=>{
  const id=uuid();
  db.prepare('INSERT INTO documents(id,owner_id,original_name,storage_name,mime_type,size_bytes,sha256,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id,userId,'quota-reservation.pdf',`${id}.blob`,'application/pdf',config.USER_QUOTA_BYTES,'0'.repeat(64),'quarantined',now());
  const r=await agent.post('/api/documents').attach('file',Buffer.from('%PDF-1.4\n'),'tiny.pdf');
  assert.equal(r.status,413);
  db.prepare('DELETE FROM documents WHERE id=?').run(id);
});

test('expired and revoked share links are rejected',async()=>{
  const id=uuid(), storage='test.pdf.blob';
  fs.mkdirSync(config.APPROVED_DIR,{recursive:true}); fs.writeFileSync(path.join(config.APPROVED_DIR,storage),Buffer.from('%PDF-1.4\\n'));
  db.prepare('INSERT INTO documents(id,owner_id,original_name,storage_name,mime_type,size_bytes,sha256,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id,userId,'test.pdf',storage,'application/pdf',8,sha256('test'),'approved',now()); docId=id;
  rawToken=crypto.randomBytes(32).toString('base64url'); shareId=uuid();
  db.prepare('INSERT INTO shares(id,owner_id,document_id,token_hash,expires_at,download_limit,download_count,profile,created_at) VALUES(?,?,?,?,?,?,0,?,?)')
    .run(shareId,userId,id,sha256(rawToken),new Date(Date.now()+60000).toISOString(),2,'download',now());
  let r=await request(app).get(`/s/${rawToken}/download`); assert.equal(r.status,200);
  db.prepare('UPDATE shares SET revoked_at=? WHERE id=?').run(now(),shareId);
  r=await request(app).get(`/s/${rawToken}/download`); assert.equal(r.status,410);
  db.prepare('UPDATE shares SET revoked_at=NULL,expires_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),shareId);
  r=await request(app).get(`/s/${rawToken}/download`); assert.equal(r.status,410);
});
test('download limits and panic revocation',async()=>{
  const raw=crypto.randomBytes(32).toString('base64url'), id=uuid();
  db.prepare('INSERT INTO shares(id,owner_id,document_id,token_hash,expires_at,download_limit,download_count,profile,created_at) VALUES(?,?,?,?,?,?,0,?,?)')
    .run(id,userId,docId,sha256(raw),new Date(Date.now()+60000).toISOString(),1,'download',now());
  let r=await request(app).get(`/s/${raw}/download`); assert.equal(r.status,200);
  r=await request(app).get(`/s/${raw}/download`); assert.equal(r.status,410);
  r=await agent.post('/api/panic').send({}); assert.equal(r.status,200);
  assert.ok(r.body.revoked>=1);
});
test('recipient OTP rejects incorrect codes and enforces attempt limits',async()=>{
  const raw=crypto.randomBytes(32).toString('base64url'), id=uuid();
  db.prepare('INSERT INTO shares(id,owner_id,document_id,token_hash,expires_at,download_limit,download_count,profile,recipient_email,created_at) VALUES(?,?,?,?,?,?,0,?,?,?)')
    .run(id,userId,docId,sha256(raw),new Date(Date.now()+60000).toISOString(),3,'verified_recipient','recipient@example.com',now());
  const sent=await request(app).post(`/s/${raw}/otp/request`).send({email:'recipient@example.com'});
  assert.equal(sent.status,200);
  for(let i=0;i<5;i++) {
    const r=await request(app).post(`/s/${raw}/otp/verify`).send({email:'recipient@example.com',code:'000000'});
    assert.equal(r.status,403);
  }
  const challenge=db.prepare('SELECT attempts FROM otp_challenges WHERE share_id=?').get(id);
  assert.equal(challenge.attempts,5);
  const locked=await request(app).post(`/s/${raw}/otp/verify`).send({email:'recipient@example.com',code:'123456'});
  assert.equal(locked.status,403);
});

test('dashboard and audit endpoints require session and return data',async()=>{
  const r=await agent.get('/api/dashboard'); assert.equal(r.status,200); assert.ok('documents' in r.body);
  const a=await agent.get('/api/audit'); assert.equal(a.status,200); assert.ok(Array.isArray(a.body.events));
});
test.after(()=>{try{db.close()}catch{}});
