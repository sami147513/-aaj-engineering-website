require('dotenv').config();
const express=require('express');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const cookieParser=require('cookie-parser');
const crypto=require('crypto');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const nodemailer=require('nodemailer');
const path=require('path');
const fs=require('fs');
const {z}=require('zod');

const app=express();
const isProd=process.env.NODE_ENV==='production';
if(isProd && !process.env.SESSION_SECRET) throw new Error('SESSION_SECRET is required in production');
const SESSION_SECRET=process.env.SESSION_SECRET||crypto.randomBytes(48).toString('hex');
const db=new Database(path.join(__dirname,'data','aaj.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'super_admin',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,admin_id INTEGER NOT NULL,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE); CREATE TABLE IF NOT EXISTS content(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,action TEXT NOT NULL,ip TEXT,created_at TEXT NOT NULL,FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE SET NULL);`);

app.disable('x-powered-by');
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:","https:"],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'self'"],frameAncestors:["'none'"]}}}));
app.use(express.json({limit:'100kb'}));
app.use(express.urlencoded({extended:false,limit:'20kb'}));
app.use(cookieParser());
const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false,message:{error:'Too many login attempts. Try again later.'}});
const apiLimiter=rateLimit({windowMs:60*1000,max:120,standardHeaders:true,legacyHeaders:false});

function sign(value){return crypto.createHmac('sha256',SESSION_SECRET).update(value).digest('base64url');}
function createSession(adminId){const id=crypto.randomBytes(32).toString('base64url');const csrf=crypto.randomBytes(32).toString('base64url');const expires=Date.now()+8*60*60*1000;db.prepare('INSERT INTO sessions(id,admin_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)').run(id,adminId,csrf,expires,Date.now());return {id,csrf,expires};}
function getSession(req){const raw=req.cookies.aaj_session;if(!raw)return null;const [id,sig]=raw.split('.');if(!id||!sig||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(sign(id))))return null;const row=db.prepare('SELECT s.*,a.username,a.role,a.active FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.id=? AND s.expires_at>? AND a.active=1').get(id,Date.now());return row||null;}
function auth(req,res,next){const s=getSession(req);if(!s)return res.status(401).json({error:'Authentication required'});req.session=s;next();}
function csrf(req,res,next){if(['GET','HEAD','OPTIONS'].includes(req.method))return next();if(req.get('X-CSRF-Token')!==req.session.csrf)return res.status(403).json({error:'Invalid CSRF token'});next();}
function audit(req,action){db.prepare('INSERT INTO audit_log(admin_id,action,ip,created_at) VALUES(?,?,?,?)').run(req.session?.admin_id||null,action,req.ip,new Date().toISOString());}

app.get('/api/health',(req,res)=>res.json({ok:true,secure:true}));
app.post('/api/login',loginLimiter,(req,res)=>{const schema=z.object({username:z.string().min(3).max(50),password:z.string().min(8).max(200)});const parsed=schema.safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid credentials'});const a=db.prepare('SELECT * FROM admins WHERE username=? AND active=1').get(parsed.data.username);if(!a||!bcrypt.compareSync(parsed.data.password,a.password_hash))return res.status(401).json({error:'Invalid username or password'});const s=createSession(a.id);res.cookie('aaj_session',`${s.id}.${sign(s.id)}`,{httpOnly:true,secure:isProd,sameSite:'strict',maxAge:8*60*60*1000,path:'/'});audit({session:{admin_id:a.id},ip:req.ip},'login');res.json({ok:true,user:{username:a.username,role:a.role},csrf:s.csrf});});
app.post('/api/logout',auth,csrf,(req,res)=>{db.prepare('DELETE FROM sessions WHERE id=?').run(req.session.id);res.clearCookie('aaj_session',{httpOnly:true,secure:isProd,sameSite:'strict',path:'/'});res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:{username:req.session.username,role:req.session.role},csrf:req.session.csrf}));
app.get('/api/content',auth,(req,res)=>{const rows=db.prepare('SELECT key,value,updated_at FROM content').all();res.json(Object.fromEntries(rows.map(r=>[r.key,{value:r.value,updated_at:r.updated_at}])));});
app.put('/api/content',auth,csrf,apiLimiter,(req,res)=>{const schema=z.record(z.string().min(1).max(100),z.string().max(20000));const parsed=schema.safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid content'});const stmt=db.prepare(`INSERT INTO content(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`);const tx=db.transaction(obj=>{const now=new Date().toISOString();for(const [k,v] of Object.entries(obj))stmt.run(k,v,now);});tx(parsed.data);audit(req,'content_update');res.json({ok:true});});
app.get('/api/audit',auth,(req,res)=>res.json(db.prepare('SELECT l.id,a.username,l.action,l.ip,l.created_at FROM audit_log l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 100').all()));

const smtpConfigured=process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS&&process.env.MAIL_FROM;
const transporter=smtpConfigured?nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE)==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
app.post('/api/rfq',apiLimiter,async(req,res)=>{const schema=z.object({name:z.string().min(2).max(100),company:z.string().max(150).optional(),email:z.string().email().max(200),phone:z.string().max(50).optional(),service:z.string().max(150).optional(),location:z.string().max(200).optional(),message:z.string().min(5).max(5000),website:z.string().max(0).optional()});const parsed=schema.safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Please check the form fields.'});if(parsed.data.website) return res.json({ok:true});const to=process.env.COMPANY_EMAIL;if(!transporter||!to)return res.status(503).json({error:'Email service is not configured yet.'});try{await transporter.sendMail({from:process.env.MAIL_FROM,to,replyTo:parsed.data.email,subject:`New AAJ RFQ — ${parsed.data.name}`,text:Object.entries(parsed.data).filter(([k])=>k!=='website').map(([k,v])=>`${k}: ${v||''}`).join('\n')});res.json({ok:true});}catch(e){console.error(e);res.status(502).json({error:'Could not send request. Please try again.'});}});

app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','secure-admin.html')));
app.use((req,res)=>res.status(404).send('Not found'));

const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`AAJ secure server running on http://localhost:${port}`));
