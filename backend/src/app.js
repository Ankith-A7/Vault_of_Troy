const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const db = require('./db');
const config = require('./config');
const { uuid, now, token, sha256, safeName, detectAndValidate, scanFile } = require('./security');
const { audit } = require('./audit');
const { sendOtp } = require('./mailer');

const app = express();
if (config.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
const allowedOrigins = new Set((process.env.FRONTEND_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173').split(',').map(v => v.trim()).filter(Boolean));
app.use(cors({ origin(origin, callback) { if (!origin || allowedOrigins.has(origin)) return callback(null, true); return callback(new Error('Origin not allowed by CORS')); }, credentials: true }));
app.use(helmet({ crossOriginResourcePolicy: { policy: 'same-site' }, contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(session({
  name: 'aegis.sid', secret: config.SESSION_SECRET, resave: false, saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.dirname(config.DB_FILE) }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: config.IS_PRODUCTION, maxAge: 8 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
const approvalPinLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', apiLimiter);

function fail(res, status, error) { return res.status(status).json({ error }); }
function validate(schema, data) {
  const r = schema.safeParse(data);
  if (!r.success) throw Object.assign(new Error('Invalid request'), { status: 400, details: r.error.flatten() });
  return r.data;
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return fail(res, 401, 'Authentication required');
  const user = db.prepare('SELECT id,email FROM users WHERE id=?').get(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return fail(res, 401, 'Authentication required'); }
  req.user = user; next();
}
function getOwnedDocument(id, userId) {
  return db.prepare("SELECT * FROM documents WHERE id=? AND owner_id=? AND deleted_at IS NULL").get(id, userId);
}
function getShare(tokenValue) {
  if (typeof tokenValue !== 'string' || tokenValue.length < 20 || tokenValue.length > 200) return null;
  return db.prepare(`SELECT s.*,d.original_name,d.storage_name,d.mime_type,d.size_bytes,d.status,d.sha256,d.owner_id AS doc_owner
    FROM shares s JOIN documents d ON d.id=s.document_id WHERE s.token_hash=? AND d.deleted_at IS NULL`)
    .get(sha256(tokenValue));
}
const upload = multer({
  dest: config.QUARANTINE_DIR,
  limits: { fileSize: config.MAX_FILE_BYTES, files: 1, fields: 8, fieldSize: 4096 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!['.pdf','.png','.jpg','.jpeg','.webp','.txt','.docx'].includes(ext)) return cb(new Error('Unsupported file extension'));
    cb(null, true);
  }
});

app.get('/api/health', (req,res) => res.json({ status:'ok', service:'Vault of Troy — Simply Secure', time:now() }));

app.post('/api/auth/register', authLimiter, async (req,res,next) => {
  try {
    const body = validate(z.object({
      email:z.string().email().max(320).transform(v=>v.toLowerCase()),
      password:z.string().min(12).max(128),
      approvalPin:z.string().regex(/^\d{6}$/, 'Approval PIN must be exactly 6 digits')
    }).strict(), req.body);
    if (db.prepare('SELECT id FROM users WHERE email=?').get(body.email)) return fail(res,409,'Email already registered');
    const id=uuid(), passwordHash=await bcrypt.hash(body.password,config.BCRYPT_ROUNDS), approvalPinHash=await bcrypt.hash(body.approvalPin,config.BCRYPT_ROUNDS);
    db.prepare('INSERT INTO users(id,email,password_hash,approval_pin_hash,created_at) VALUES(?,?,?,?,?)').run(id,body.email,passwordHash,approvalPinHash,now());
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId=id;
      audit({actorId:id,event:'register',ip:req.ip});
      res.status(201).json({user:{id,email:body.email}});
    });
  } catch(e) { next(e); }
});
app.post('/api/auth/login', authLimiter, async (req,res,next) => {
  try {
    const body=validate(z.object({email:z.string().email().max(320).transform(v=>v.toLowerCase()),password:z.string().min(1).max(128)}).strict(),req.body);
    const user=db.prepare('SELECT * FROM users WHERE email=?').get(body.email);
    const ok=user && await bcrypt.compare(body.password,user.password_hash);
    if (!ok) { audit({event:'login',outcome:'rejected',ip:req.ip,details:{reason:'invalid_credentials'}}); return fail(res,401,'Invalid email or password'); }
    req.session.regenerate(err=> {
      if(err) return next(err);
      req.session.userId=user.id;
      audit({actorId:user.id,event:'login',ip:req.ip});
      res.json({user:{id:user.id,email:user.email}});
    });
  } catch(e) { next(e); }
});
app.post('/api/auth/logout', requireAuth, (req,res) => {
  const id=req.user.id;
  req.session.destroy(err=> {
    if(err) return fail(res,500,'Could not end session');
    res.clearCookie('aegis.sid',{httpOnly:true,sameSite:'lax',secure:config.IS_PRODUCTION});
    audit({actorId:id,event:'logout',ip:req.ip}); res.json({ok:true});
  });
});
app.get('/api/auth/me', requireAuth, (req,res)=>res.json({user:req.user}));

// Existing accounts can set an approval PIN after re-authenticating with their password.
app.post('/api/auth/approval-pin', requireAuth, approvalPinLimiter, async (req,res,next)=>{
  try {
    const body=validate(z.object({password:z.string().min(1).max(128),approvalPin:z.string().regex(/^\d{6}$/,'Approval PIN must be exactly 6 digits')}).strict(),req.body);
    const user=db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
    if(!user || !(await bcrypt.compare(body.password,user.password_hash))) return fail(res,401,'Password verification failed');
    const pinHash=await bcrypt.hash(body.approvalPin,config.BCRYPT_ROUNDS);
    db.prepare('UPDATE users SET approval_pin_hash=? WHERE id=?').run(pinHash,req.user.id);
    audit({actorId:req.user.id,event:'approval_pin_set',ip:req.ip});
    res.json({ok:true});
  } catch(e){next(e);}
});

app.post('/api/documents', requireAuth, (req,res,next) => {
  upload.single('file')(req,res,async err=>{
    if(err) {
      audit({actorId:req.user.id,event:'upload',outcome:'rejected',ip:req.ip,details:{reason:err.code||err.message}});
      if(err instanceof multer.MulterError && err.code==='LIMIT_FILE_SIZE') return fail(res,413,'File exceeds configured size limit');
      return fail(res,400,err.message || 'Upload rejected');
    }
    if(!req.file) return fail(res,400,'A file is required');
    const temp=req.file.path;
    try {
      const mime=await detectAndValidate(temp,req.file.originalname);
      const storageName=`${crypto.randomUUID()}.blob`;
      const bytes=await fs.readFile(temp);
      const digest=crypto.createHash('sha256').update(bytes).digest('hex');
      const id=uuid();
      // Reserve quota and create the metadata row in one synchronous SQLite transaction.
      // This prevents simultaneous uploads from both passing a stale quota check.
      const reserved=db.transaction(()=>{
        const used=db.prepare("SELECT COALESCE(SUM(size_bytes),0) AS n FROM documents WHERE owner_id=? AND deleted_at IS NULL").get(req.user.id).n;
        if(used+req.file.size>config.USER_QUOTA_BYTES) return false;
        db.prepare(`INSERT INTO documents(id,owner_id,original_name,storage_name,mime_type,size_bytes,sha256,status,created_at)
          VALUES(?,?,?,?,?,?,?,?,?)`).run(id,req.user.id,safeName(req.file.originalname),storageName,mime,req.file.size,digest,'quarantined',now());
        return true;
      })();
      if(!reserved) { await fs.unlink(temp).catch(()=>{}); audit({actorId:req.user.id,event:'upload',outcome:'rejected',ip:req.ip,details:{reason:'quota'}}); return fail(res,413,'User storage quota exceeded'); }
      const scan=await scanFile(temp);
      let status='quarantined';
      // A clean scan is necessary; missing/failed scanner means quarantine, never public access.
      const targetDir=scan.clean?config.APPROVED_DIR:config.QUARANTINE_DIR;
      status=scan.clean?'approved':(scan.reason==='malware_detected'?'rejected':'quarantined');
      try {
        await fs.rename(temp,path.join(targetDir,storageName));
        db.prepare('UPDATE documents SET status=? WHERE id=? AND owner_id=?').run(status,id,req.user.id);
      } catch(moveError) {
        db.prepare('DELETE FROM documents WHERE id=? AND owner_id=?').run(id,req.user.id);
        throw moveError;
      }
      audit({actorId:req.user.id,documentId:id,event:'upload',outcome:status==='approved'?'success':'quarantined',ip:req.ip,details:{size:req.file.size,mime,scan:scan.reason}});
      res.status(201).json({document:{id,name:safeName(req.file.originalname),mimeType:mime,sizeBytes:req.file.size,status,sha256:digest,createdAt:now()},safety:{status,scanner:scan.reason}});
    } catch(e) {
      await fs.unlink(temp).catch(()=>{});
      audit({actorId:req.user.id,event:'upload',outcome:'rejected',ip:req.ip,details:{reason:e.message}});
      next(e);
    }
  });
});

app.get('/api/documents',requireAuth,(req,res)=>{
  const docs=db.prepare("SELECT id,original_name AS name,mime_type AS mimeType,size_bytes AS sizeBytes,status,sha256,created_at AS createdAt FROM documents WHERE owner_id=? AND deleted_at IS NULL ORDER BY created_at DESC").all(req.user.id);
  res.json({documents:docs,quota:{usedBytes:docs.reduce((a,d)=>a+d.sizeBytes,0),maxBytes:config.USER_QUOTA_BYTES}});
});
app.get('/api/documents/:id',requireAuth,(req,res)=>{
  const d=getOwnedDocument(req.params.id,req.user.id);
  if(!d) return fail(res,404,'Document not found');
  res.json({document:{id:d.id,name:d.original_name,mimeType:d.mime_type,sizeBytes:d.size_bytes,status:d.status,sha256:d.sha256,createdAt:d.created_at}});
});
app.post('/api/documents/:id/approve', requireAuth, approvalPinLimiter, async(req,res,next)=>{
  try {
    const body=validate(z.object({approvalPin:z.string().regex(/^\d{6}$/,'Enter your 6-digit approval PIN'), acknowledgeRisk:z.literal(true)}).strict(),req.body);
    const user=db.prepare('SELECT approval_pin_hash FROM users WHERE id=?').get(req.user.id);
    if(!user?.approval_pin_hash) return fail(res,409,'Set an approval PIN in your account before approving quarantined files');
    if(!(await bcrypt.compare(body.approvalPin,user.approval_pin_hash))){
      audit({actorId:req.user.id,documentId:req.params.id,event:'document_approval',outcome:'rejected',ip:req.ip,details:{reason:'invalid_approval_pin'}});
      return fail(res,401,'Incorrect approval PIN');
    }
    const d=getOwnedDocument(req.params.id,req.user.id);
    if(!d) return fail(res,404,'Document not found');
    if(d.status!=='quarantined') return fail(res,409,`Only quarantined files can be approved (current status: ${d.status})`);
    const source=path.join(config.QUARANTINE_DIR,d.storage_name);
    const destination=path.join(config.APPROVED_DIR,d.storage_name);
    // Owner-authorized release is auditable but is NOT a malware scan. User explicitly accepts this risk.
    await fs.access(source);
    await fs.rename(source,destination);
    const changed=db.prepare("UPDATE documents SET status='approved' WHERE id=? AND owner_id=? AND status='quarantined' AND deleted_at IS NULL").run(d.id,req.user.id);
    if(changed.changes!==1){ await fs.rename(destination,source).catch(()=>{}); return fail(res,409,'Document status changed; refresh and try again'); }
    audit({actorId:req.user.id,documentId:d.id,event:'document_approval',outcome:'success',ip:req.ip,details:{method:'owner_pin_authorized_release',scanner_bypassed:true}});
    res.json({ok:true,document:{id:d.id,status:'approved'},warning:'Owner-authorized release recorded. The file was not confirmed malware-free by a scanner.'});
  } catch(e){ if(e.code==='ENOENT') return fail(res,409,'Quarantined file is missing from storage'); next(e); }
});

app.delete('/api/documents/:id',requireAuth,async(req,res,next)=>{
  try {
    const d=getOwnedDocument(req.params.id,req.user.id);
    if(!d) return fail(res,404,'Document not found');
    const t=now();
    const tx=db.transaction(()=>{
      db.prepare('UPDATE shares SET revoked_at=? WHERE document_id=? AND revoked_at IS NULL').run(t,d.id);
      db.prepare('UPDATE documents SET deleted_at=? WHERE id=? AND owner_id=?').run(t,d.id,req.user.id);
      audit({actorId:req.user.id,documentId:d.id,event:'delete',ip:req.ip});
    }); tx();
    await fs.unlink(path.join(d.status==='approved'?config.APPROVED_DIR:config.QUARANTINE_DIR,d.storage_name)).catch(()=>{});
    res.json({ok:true});
  } catch(e){next(e);}
});

app.post('/api/shares',requireAuth,(req,res,next)=>{
  try {
    const body=validate(z.object({
      documentId:z.string().uuid(),
      expiresInHours:z.number().int().positive().max(config.MAX_SHARE_HOURS).default(config.DEFAULT_SHARE_HOURS),
      downloadLimit:z.number().int().positive().max(1000).default(config.DEFAULT_DOWNLOAD_LIMIT),
      profile:z.enum(['view_only','download','one_time','verified_recipient']).default('download'),
      recipientEmail:z.string().email().max(320).optional()
    }).strict(),req.body);
    const doc=getOwnedDocument(body.documentId,req.user.id);
    if(!doc) return fail(res,404,'Document not found');
    if(doc.status!=='approved') return fail(res,423,'Document is quarantined or rejected and cannot be shared');
    if(body.profile==='view_only' && doc.mime_type!=='application/pdf') return fail(res,400,'View-only preview currently supports PDF documents only');
    if(body.profile==='verified_recipient'&&!body.recipientEmail) return fail(res,400,'recipientEmail is required for verified-recipient profile');
    if(db.prepare("SELECT COUNT(*) n FROM shares WHERE owner_id=? AND revoked_at IS NULL AND expires_at>?").get(req.user.id,now()).n>=config.MAX_ACTIVE_SHARES) return fail(res,429,'Active share limit reached');
    const raw=token(32),id=uuid(),created=now(),expires=new Date(Date.now()+body.expiresInHours*3600000).toISOString();
    db.prepare(`INSERT INTO shares(id,owner_id,document_id,token_hash,expires_at,download_limit,profile,recipient_email,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)`).run(id,req.user.id,doc.id,sha256(raw),expires,body.profile==='one_time'?1:body.downloadLimit,body.profile,body.recipientEmail?.toLowerCase()||null,created);
    audit({actorId:req.user.id,documentId:doc.id,shareId:id,event:'share_create',ip:req.ip,details:{profile:body.profile,expiresAt:expires,downloadLimit:body.profile==='one_time'?1:body.downloadLimit}});
    res.status(201).json({share:{id,documentId:doc.id,expiresAt:expires,downloadLimit:body.profile==='one_time'?1:body.downloadLimit,profile:body.profile,recipientEmail:body.recipientEmail||null,url:`${config.BASE_URL}/s/${raw}`,token:raw,createdAt:created}});
  }catch(e){next(e);}
});
app.get('/api/shares',requireAuth,(req,res)=>{
  const rows=db.prepare(`SELECT s.id,s.document_id AS documentId,d.original_name AS documentName,s.expires_at AS expiresAt,
    s.download_limit AS downloadLimit,s.download_count AS downloadCount,s.profile,s.recipient_email AS recipientEmail,
    s.revoked_at AS revokedAt,s.created_at AS createdAt FROM shares s JOIN documents d ON d.id=s.document_id
    WHERE s.owner_id=? ORDER BY s.created_at DESC`).all(req.user.id);
  res.json({shares:rows});
});
app.delete('/api/shares/:id',requireAuth,(req,res)=>{
  const s=db.prepare('SELECT * FROM shares WHERE id=? AND owner_id=?').get(req.params.id,req.user.id);
  if(!s) return fail(res,404,'Share not found');
  if(!s.revoked_at) db.prepare('UPDATE shares SET revoked_at=? WHERE id=? AND owner_id=?').run(now(),s.id,req.user.id);
  audit({actorId:req.user.id,documentId:s.document_id,shareId:s.id,event:'share_revoke',ip:req.ip});
  res.json({ok:true,revoked:true});
});
app.post('/api/panic',requireAuth,(req,res)=>{
  const t=now();
  const result=db.prepare('UPDATE shares SET revoked_at=? WHERE owner_id=? AND revoked_at IS NULL').run(t,req.user.id);
  audit({actorId:req.user.id,event:'panic_revoke_all',ip:req.ip,details:{revoked:result.changes}});
  res.json({ok:true,revoked:result.changes});
});

app.get('/s/:token',async(req,res,next)=>{
  try {
    const s=getShare(req.params.token);
    if(!s) { audit({event:'share_access',outcome:'rejected',ip:req.ip,details:{reason:'invalid_token'}}); return fail(res,404,'Share link not found'); }
    if(s.revoked_at) { audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'share_access',outcome:'rejected',ip:req.ip,details:{reason:'revoked'}}); return fail(res,410,'This share link has been revoked'); }
    if(Date.parse(s.expires_at)<=Date.now()) { audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'share_access',outcome:'rejected',ip:req.ip,details:{reason:'expired'}}); return fail(res,410,'This share link has expired'); }
    if(s.download_count>=s.download_limit) return fail(res,410,'Download limit reached');
    const challenge=db.prepare('SELECT * FROM otp_challenges WHERE share_id=? AND email=?').get(s.id,s.recipient_email||'');
    const verified=s.profile!=='verified_recipient'||(challenge&&challenge.verified_at&&Date.parse(challenge.expires_at)>Date.now());
    res.json({share:{id:s.id,name:s.original_name,mimeType:s.mime_type,sizeBytes:s.size_bytes,expiresAt:s.expires_at,profile:s.profile,downloadCount:s.download_count,downloadLimit:s.download_limit,verified,canPreview:s.profile==='view_only'&&s.mime_type==='application/pdf'}});
  }catch(e){next(e);}
});
app.post('/s/:token/otp/request',async(req,res,next)=>{
  try {
    const s=getShare(req.params.token);
    if(!s||s.revoked_at||Date.parse(s.expires_at)<=Date.now()) return fail(res,404,'Share link is unavailable');
    if(s.profile!=='verified_recipient') return fail(res,400,'This share does not require recipient verification');
    const email=String(req.body.email||'').toLowerCase();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email!==String(s.recipient_email).toLowerCase()) return fail(res,403,'Recipient email does not match');
    const previous=db.prepare('SELECT * FROM otp_challenges WHERE share_id=? AND email=?').get(s.id,email);
    if(previous&&Date.now()-Date.parse(previous.last_sent_at)<config.OTP_RESEND_SECONDS*1000) return fail(res,429,'Please wait before requesting another code');
    const code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
    const id=uuid(),sent=now(),expires=new Date(Date.now()+config.OTP_TTL_MINUTES*60000).toISOString();
    db.prepare(`INSERT INTO otp_challenges(id,share_id,email,code_hash,expires_at,attempts,last_sent_at,verified_at)
      VALUES(?,?,?,?,?,0,?,NULL) ON CONFLICT(id) DO NOTHING`).run(id,s.id,email,sha256(`${id}:${code}`),expires,sent);
    // Keep only the newest challenge per share/email.
    db.prepare('DELETE FROM otp_challenges WHERE share_id=? AND email=? AND id<>?').run(s.id,email,id);
    await sendOtp(email,code);
    audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'otp_send',ip:req.ip});
    res.json({ok:true,message:'Verification code sent'});
  }catch(e){next(e);}
});
app.post('/s/:token/otp/verify',(req,res)=>{
  const s=getShare(req.params.token);
  if(!s||s.revoked_at||Date.parse(s.expires_at)<=Date.now()) return fail(res,404,'Share link is unavailable');
  const email=String(req.body.email||'').toLowerCase(),code=String(req.body.code||'');
  const c=db.prepare('SELECT * FROM otp_challenges WHERE share_id=? AND email=?').get(s.id,email);
  if(!c||c.verified_at||Date.parse(c.expires_at)<=Date.now()||c.attempts>=config.OTP_MAX_ATTEMPTS) return fail(res,403,'Code is invalid or expired');
  const valid=crypto.timingSafeEqual(Buffer.from(c.code_hash),Buffer.from(sha256(`${c.id}:${code}`)));
  if(!valid) {
    db.prepare('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?').run(c.id);
    audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'otp_verify',outcome:'rejected',ip:req.ip,details:{reason:'bad_code'}});
    return fail(res,403,'Code is invalid or expired');
  }
  db.prepare('UPDATE otp_challenges SET verified_at=? WHERE id=?').run(now(),c.id);
  audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'otp_verify',ip:req.ip});
  res.json({ok:true,verified:true});
});

app.get('/s/:token/preview', (req,res)=>{
  const s=getShare(req.params.token);
  if(!s || s.revoked_at || Date.parse(s.expires_at)<=Date.now() || s.status!=='approved') {
    audit({event:'preview',outcome:'rejected',ip:req.ip,details:{reason:'unavailable'}});
    return fail(res,404,'File is unavailable');
  }
  if(s.profile!=='view_only' || s.mime_type!=='application/pdf') return fail(res,403,'Inline preview is available only for view-only PDF shares');
  const filePath=path.join(config.APPROVED_DIR,s.storage_name);
  res.set({'Content-Type':'application/pdf','Content-Disposition':'inline; filename="document.pdf"',
    'X-Content-Type-Options':'nosniff','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; sandbox",
    'Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'});
  res.sendFile(filePath,err=>{ if(err && !res.headersSent) console.error(err); });
});

app.get('/s/:token/download', (req,res,next)=>{
  const s=getShare(req.params.token);
  if(!s) { audit({event:'download',outcome:'rejected',ip:req.ip,details:{reason:'invalid_token'}}); return fail(res,404,'Share link not found'); }
  if(s.revoked_at) { audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'download',outcome:'rejected',ip:req.ip,details:{reason:'revoked'}}); return fail(res,410,'This share link has been revoked'); }
  if(Date.parse(s.expires_at)<=Date.now()) { audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'download',outcome:'rejected',ip:req.ip,details:{reason:'expired'}}); return fail(res,410,'This share link has expired'); }
  if(s.status!=='approved') return fail(res,423,'File is not approved for download');
  if(s.profile==='view_only') return fail(res,403,'This share is view-only');
  const verified=s.profile!=='verified_recipient'||db.prepare('SELECT id FROM otp_challenges WHERE share_id=? AND email=? AND verified_at IS NOT NULL AND expires_at>?').get(s.id,s.recipient_email,now());
  if(!verified) return fail(res,403,'Recipient verification required');
  const filePath=path.join(config.APPROVED_DIR,s.storage_name);
  // Atomic guarded increment avoids concurrent requests exceeding the configured limit.
  const tx=db.transaction(()=>{
    const current=db.prepare('SELECT download_count,download_limit,revoked_at,expires_at FROM shares WHERE id=?').get(s.id);
    if(!current||current.revoked_at||Date.parse(current.expires_at)<=Date.now()||current.download_count>=current.download_limit) return false;
    const updated=db.prepare('UPDATE shares SET download_count=download_count+1 WHERE id=? AND download_count<download_limit AND revoked_at IS NULL').run(s.id);
    if(!updated.changes) return false;
    audit({actorId:s.owner_id,documentId:s.document_id,shareId:s.id,event:'download',ip:req.ip,details:{count:current.download_count+1}});
    return true;
  });
  if(!tx()) return fail(res,410,'Download limit reached or link unavailable');
  res.set({
    'Content-Type':s.mime_type, 'Content-Disposition':`attachment; filename="${safeName(s.original_name).replace(/["\\]/g,'_')}"`,
    'X-Content-Type-Options':'nosniff', 'Cache-Control':'no-store', 'Content-Security-Policy':"default-src 'none'; sandbox",
    'Referrer-Policy':'no-referrer'
  });
  res.sendFile(filePath,err=>{if(err&&!res.headersSent) next(err);});
});

app.get('/api/dashboard',requireAuth,(req,res)=>{
  const docs=db.prepare("SELECT COUNT(*) n,COALESCE(SUM(size_bytes),0) bytes FROM documents WHERE owner_id=? AND deleted_at IS NULL").get(req.user.id);
  const shares=db.prepare("SELECT COUNT(*) total,SUM(CASE WHEN revoked_at IS NULL AND expires_at>? THEN 1 ELSE 0 END) active,COALESCE(SUM(download_count),0) downloads FROM shares WHERE owner_id=?").get(now(),req.user.id);
  const events=db.prepare('SELECT COUNT(*) n FROM audit_events WHERE actor_id=?').get(req.user.id);
  res.json({documents:docs.n,usedBytes:docs.bytes,quotaBytes:config.USER_QUOTA_BYTES,totalShares:shares.total,activeShares:shares.active||0,downloads:shares.downloads,auditEvents:events.n});
});
app.get('/api/audit',requireAuth,(req,res)=>{
  const limit=Math.min(Math.max(Number(req.query.limit)||50,1),200);
  const events=db.prepare(`SELECT a.id,a.event_type AS event,a.outcome,a.details_json AS details,a.created_at AS createdAt,
    d.original_name AS documentName FROM audit_events a LEFT JOIN documents d ON d.id=a.document_id
    WHERE a.actor_id=? ORDER BY a.created_at DESC LIMIT ?`).all(req.user.id,limit).map(e=>({...e,details:JSON.parse(e.details)}));
  res.json({events});
});
app.get('/api/confidentiality-map',requireAuth,(req,res)=>{
  const docs=db.prepare("SELECT id,original_name AS name,status,size_bytes AS sizeBytes,created_at AS createdAt FROM documents WHERE owner_id=? AND deleted_at IS NULL").all(req.user.id);
  const shares=db.prepare(`SELECT s.id,s.document_id AS documentId,s.profile,s.expires_at AS expiresAt,s.download_count AS downloads,s.download_limit AS downloadLimit,
    CASE WHEN s.revoked_at IS NOT NULL THEN 'revoked' WHEN s.expires_at<=? THEN 'expired' ELSE 'active' END AS state
    FROM shares s WHERE s.owner_id=?`).all(now(),req.user.id);
  res.json({nodes:[...docs.map(d=>({id:d.id,type:'document',label:d.name,status:d.status,sizeBytes:d.sizeBytes})),...shares.map(s=>({id:s.id,type:'share',documentId:s.documentId,profile:s.profile,state:s.state,expiresAt:s.expiresAt,downloads:s.downloads,downloadLimit:s.downloadLimit}))]});
});

app.use((req,res)=>fail(res,404,'Endpoint not found'));
app.use((err,req,res,next)=>{
  if(res.headersSent) return next(err);
  const status=err.status||500;
  if(status>=500) console.error(err);
  res.status(status).json({error:status>=500?'Internal server error':err.message, ...(err.details?{details:err.details}:{})});
});
module.exports=app;
