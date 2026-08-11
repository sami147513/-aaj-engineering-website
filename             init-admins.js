require('dotenv').config();
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const dbPath = path.join(__dirname,'data','aaj.db');
fs.mkdirSync(path.dirname(dbPath),{recursive:true});
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'super_admin',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS content(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL);`);
const users=[['admin1',process.env.ADMIN1_PASSWORD],['admin2',process.env.ADMIN2_PASSWORD],['admin3',process.env.ADMIN3_PASSWORD]];
const now=new Date().toISOString();
for(const [username,password] of users){if(!password||password.startsWith('CHANGE_THIS')){console.error(`Set ${username.toUpperCase()}_PASSWORD in .env before running init-admins.js`);process.exitCode=1;continue;} const hash=bcrypt.hashSync(password,12); db.prepare(`INSERT INTO admins(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role,active=1`).run(username,hash,'super_admin',1,now);}
const defaults={company_email:process.env.COMPANY_EMAIL||'',management_message:'',about_text:'',contact_phone:'',contact_address:''};
for(const [key,value] of Object.entries(defaults)) db.prepare(`INSERT INTO content(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING`).run(key,value,now);
console.log('Database initialized. Three admin accounts created/updated with super_admin access.');
