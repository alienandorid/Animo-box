import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { randomUUID, randomInt, createHmac, timingSafeEqual } from 'node:crypto';
import { rateLimit } from 'express-rate-limit';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProd ? { rejectUnauthorized: false } : undefined });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static('public'));

const apiLimit = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
const otpLimit = rateLimit({ windowMs: 10 * 60_000, limit: 4, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'অনেকবার চেষ্টা হয়েছে। ১০ মিনিট পরে আবার চেষ্টা করুন।' } });
app.use('/api', apiLimit);

const seedProducts = [
  ['Anime Figure - Hero Edition','Figures','🧍',1850,2190,'Collectibles'],
  ['Anime Oversized T-Shirt','Clothing','👕',790,990,'Fashion'],
  ['LED Anime Desk Lamp','Accessories','💡',1250,1490,'Lifestyle'],
  ['Manga Art Poster Set','Wall Art','🖼️',450,590,'Decor'],
  ['Anime Keychain Pack','Accessories','🔑',290,390,'Collectibles'],
  ['Gaming Headset','Electronics','🎧',1890,2290,'Electronics'],
  ['Manga Notebook','Stationery','📓',380,490,'Stationery'],
  ['Anime Backpack','Bags','🎒',1450,1790,'Fashion']
];

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, emoji TEXT DEFAULT '📦', price INTEGER NOT NULL CHECK(price >= 0), compare_price INTEGER, description TEXT DEFAULT '', stock INTEGER NOT NULL DEFAULT 20, active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS otp_challenges (id UUID PRIMARY KEY, phone TEXT NOT NULL, provider_ref TEXT, otp_hash TEXT, attempts INTEGER NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, verified_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW());
    ALTER TABLE otp_challenges ADD COLUMN IF NOT EXISTS otp_hash TEXT;
    ALTER TABLE otp_challenges ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS orders (id BIGSERIAL PRIMARY KEY, order_code TEXT UNIQUE NOT NULL, customer_name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, division TEXT NOT NULL, district TEXT NOT NULL, area TEXT NOT NULL, address TEXT NOT NULL, note TEXT DEFAULT '', items JSONB NOT NULL, subtotal INTEGER NOT NULL, delivery_fee INTEGER NOT NULL, total INTEGER NOT NULL, payment_method TEXT NOT NULL DEFAULT 'COD', status TEXT NOT NULL DEFAULT 'Pending confirmation', verified_phone BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE INDEX IF NOT EXISTS orders_created_idx ON orders(created_at DESC);
    CREATE INDEX IF NOT EXISTS orders_phone_idx ON orders(phone);
  `);
  const count = await pool.query('SELECT COUNT(*)::int AS n FROM products');
  if (count.rows[0].n === 0) {
    for (const p of seedProducts) await pool.query('INSERT INTO products(name,category,emoji,price,compare_price,description,stock) VALUES($1,$2,$3,$4,$5,$6,20)', [...p.slice(0,5), `${p[0]} — ANIME BOX-এর নির্বাচিত কালেকশন।`]);
  }
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
    const exists = await pool.query('SELECT id FROM admins WHERE email=$1', [email]);
    if (!exists.rowCount) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query('INSERT INTO admins(email,password_hash) VALUES($1,$2)', [email, hash]);
      console.log('Initial admin account created from environment variables.');
    }
  }
}

function normalizeBdPhone(input) {
  const digits = String(input || '').replace(/[\s()-]/g, '');
  if (/^01[3-9]\d{8}$/.test(digits)) return `+88${digits}`;
  if (/^8801[3-9]\d{8}$/.test(digits)) return `+${digits}`;
  if (/^\+8801[3-9]\d{8}$/.test(digits)) return digits;
  return null;
}
function otpConfigured() {
  return Boolean(process.env.W3SMS_API_KEY && process.env.W3SMS_SENDER_ID && process.env.OTP_SECRET && process.env.OTP_SECRET.length >= 32);
}
function otpDigest(challengeId, phone, code) {
  return createHmac('sha256', process.env.OTP_SECRET).update(`${challengeId}:${phone}:${code}`).digest('hex');
}
async function sendOtpSms(phone, code) {
  const response = await fetch('https://w3sms.com/api/v1/sms/send', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.W3SMS_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: phone, from: process.env.W3SMS_SENDER_ID, text: `ANIME BOX verification code: ${code}. Valid for 5 minutes. Do not share this code.`, type: 'transactional' })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.id || (data.status && !['queued','sent','accepted','success'].includes(String(data.status).toLowerCase()))) {
    throw new Error(`SMS gateway rejected request (HTTP ${response.status})`);
  }
  return data.id;
}

function adminAuth(req, res, next) {
  const token = req.cookies.ab_admin;
  if (!token || !process.env.JWT_SECRET) return res.status(401).json({ error: 'প্রথমে অ্যাডমিন লগইন করুন।' });
  try { req.admin = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.clearCookie('ab_admin'); return res.status(401).json({ error: 'সেশন শেষ হয়েছে। আবার লগইন করুন।' }); }
}

app.get('/api/health', (_req, res) => res.json({ ok: true, store: 'ANIME BOX', time: new Date().toISOString() }));
app.get('/api/config', (_req, res) => res.json({ storeName: 'ANIME BOX', otpConfigured: otpConfigured(), otpProvider: 'W3 SMS transactional gateway (operator coverage subject to account route and sender approval)' }));
app.get('/api/products', async (_req, res) => {
  try { const r = await pool.query('SELECT id,name,category,emoji,price,compare_price,description,stock FROM products WHERE active=TRUE ORDER BY id'); res.json(r.rows); }
  catch (e) { console.error(e); res.status(500).json({ error: 'পণ্য লোড করা যায়নি।' }); }
});

app.post('/api/otp/request', otpLimit, async (req, res) => {
  const phone = normalizeBdPhone(req.body.phone);
  if (!phone) return res.status(400).json({ error: 'সঠিক বাংলাদেশি মোবাইল নম্বর দিন।' });
  if (!otpConfigured()) return res.status(503).json({ error: 'আসল OTP চালু করতে W3 SMS API key, অনুমোদিত sender ID এবং OTP_SECRET সেট করতে হবে।' });
  try {
    const recent = await pool.query("SELECT COUNT(*)::int AS n FROM otp_challenges WHERE phone=$1 AND created_at > NOW() - INTERVAL '30 minutes'", [phone]);
    if (recent.rows[0].n >= 3) return res.status(429).json({ error: 'এই নম্বরে সাময়িকভাবে OTP সীমা পূর্ণ হয়েছে। পরে চেষ্টা করুন।' });
    const challengeId = randomUUID();
    const code = String(randomInt(100000, 1000000));
    const messageId = await sendOtpSms(phone, code);
    await pool.query('INSERT INTO otp_challenges(id,phone,provider_ref,otp_hash,expires_at) VALUES($1,$2,$3,$4,NOW()+INTERVAL \'5 minutes\')', [challengeId, phone, String(messageId), otpDigest(challengeId, phone, code)]);
    res.json({ ok: true, challengeId, message: 'তোমার নম্বরে ৬ সংখ্যার OTP পাঠানো হয়েছে। ৫ মিনিটের মধ্যে কোডটি দিন।' });
  } catch (e) { console.error('OTP request error:', e.message); res.status(502).json({ error: 'SMS পাঠানো যায়নি। API key, sender ID approval ও gateway balance পরীক্ষা করুন।' }); }
});

app.post('/api/orders/track', otpLimit, async (req,res) => {
  const code=String(req.body.orderCode||'').trim().toUpperCase();
  const phone=normalizeBdPhone(req.body.phone);
  if(!code||!phone)return res.status(400).json({error:'অর্ডার নম্বর ও সঠিক মোবাইল নম্বর দিন।'});
  try{const r=await pool.query('SELECT order_code,status,total,items,created_at,updated_at FROM orders WHERE order_code=$1 AND phone=$2',[code,phone]);if(!r.rowCount)return res.status(404).json({error:'এই তথ্য দিয়ে কোনো অর্ডার পাওয়া যায়নি।'});res.json({order:r.rows[0]});}
  catch(e){console.error(e);res.status(500).json({error:'অর্ডার খোঁজা যায়নি।'});}
});

app.post('/api/orders', otpLimit, async (req, res) => {
  const { challengeId, otp, customer = {}, items = [] } = req.body;
  if (!challengeId || !/^\d{4,8}$/.test(String(otp || ''))) return res.status(400).json({ error: 'OTP এবং verification reference প্রয়োজন।' });
  const phone = normalizeBdPhone(customer.phone);
  if (!phone) return res.status(400).json({ error: 'সঠিক বাংলাদেশি মোবাইল নম্বর দিন।' });
  const required = ['name','division','district','area','address'];
  if (required.some(k => !String(customer[k] || '').trim())) return res.status(400).json({ error: 'নাম ও সম্পূর্ণ ডেলিভারি ঠিকানা পূরণ করুন।' });
  if (!Array.isArray(items) || items.length < 1 || items.length > 30) return res.status(400).json({ error: 'কার্টে পণ্য যোগ করুন।' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const challenge = await client.query('SELECT * FROM otp_challenges WHERE id=$1 AND phone=$2 AND verified_at IS NULL AND expires_at>NOW() AND attempts<5 FOR UPDATE', [challengeId, phone]);
    if (!challenge.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'OTP সেশনটি মেয়াদোত্তীর্ণ বা ভুল। নতুন OTP নিন।' }); }
    if (!otpConfigured()) { await client.query('ROLLBACK'); return res.status(503).json({ error: 'OTP gateway configuration পাওয়া যায়নি।' }); }
    const storedHash = challenge.rows[0].otp_hash || '';
    const suppliedHash = otpDigest(challengeId, phone, String(otp));
    const validHash = storedHash.length === suppliedHash.length && timingSafeEqual(Buffer.from(storedHash), Buffer.from(suppliedHash));
    if (!validHash) {
      await client.query('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=$1', [challengeId]);
      await client.query('COMMIT');
      return res.status(400).json({ error: 'OTP সঠিক নয়। সর্বোচ্চ ৫ বার চেষ্টা করা যাবে।' });
    }
    if (Number(challenge.rows[0].attempts) >= 5) { await client.query('ROLLBACK'); return res.status(429).json({ error: 'ভুল OTP চেষ্টার সীমা শেষ। নতুন OTP নিন।' }); }
    await client.query('UPDATE otp_challenges SET verified_at=NOW() WHERE id=$1', [challengeId]);
    const ids = [...new Set(items.map(x => Number(x.id)).filter(Number.isInteger))];
    const products = await client.query('SELECT id,name,category,emoji,price,stock FROM products WHERE active=TRUE AND id=ANY($1::int[]) FOR UPDATE', [ids]);
    const map = new Map(products.rows.map(p => [p.id, p]));
    let subtotal = 0; const cleanItems = [];
    for (const item of items) {
      const p = map.get(Number(item.id)); const qty = Math.max(0, Math.min(10, Math.floor(Number(item.quantity))));
      if (!p || !qty || p.stock < qty) throw new Error(`পণ্য ${item.id} বর্তমানে পর্যাপ্ত স্টকে নেই।`);
      subtotal += p.price * qty; cleanItems.push({ id:p.id, name:p.name, category:p.category, emoji:p.emoji, unitPrice:p.price, quantity:qty, lineTotal:p.price*qty });
    }
    const delivery = subtotal >= 3000 ? 0 : 80; const total = subtotal + delivery;
    const orderCode = `AB${Date.now().toString().slice(-8)}${Math.floor(10+Math.random()*90)}`;
    const inserted = await client.query(`INSERT INTO orders(order_code,customer_name,phone,email,division,district,area,address,note,items,subtotal,delivery_fee,total,payment_method,verified_phone)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'Cash on Delivery',TRUE) RETURNING order_code,total,status`,
      [orderCode, String(customer.name).trim(), phone, customer.email || null, customer.division, customer.district, customer.area, customer.address, customer.note || '', JSON.stringify(cleanItems), subtotal, delivery, total]);
    for (const item of cleanItems) await client.query('UPDATE products SET stock=stock-$1 WHERE id=$2', [item.quantity,item.id]);
    await client.query('COMMIT');
    res.status(201).json({ ok:true, order: inserted.rows[0] });
  } catch (e) { await client.query('ROLLBACK'); console.error('Order error:',e.message); res.status(400).json({ error: e.message || 'অর্ডার তৈরি করা যায়নি।' }); }
  finally { client.release(); }
});

app.post('/api/admin/login', async (req,res) => {
  const email=String(req.body.email||'').toLowerCase().trim(), password=String(req.body.password||'');
  if (!email || !password || !process.env.JWT_SECRET) return res.status(400).json({error:'লগইন তথ্য বা সার্ভার কনফিগারেশন সঠিক নয়।'});
  try {
    const r=await pool.query('SELECT id,email,password_hash FROM admins WHERE email=$1',[email]);
    if (!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:'ইমেইল বা পাসওয়ার্ড সঠিক নয়।'});
    const token=jwt.sign({id:r.rows[0].id,email:r.rows[0].email},process.env.JWT_SECRET,{expiresIn:'8h'});
    res.cookie('ab_admin',token,{httpOnly:true,secure:isProd,sameSite:'strict',maxAge:8*60*60*1000});
    res.json({ok:true,email:r.rows[0].email});
  } catch(e){console.error(e);res.status(500).json({error:'লগইন করা যায়নি।'});}
});
app.post('/api/admin/logout',(_req,res)=>{res.clearCookie('ab_admin',{httpOnly:true,secure:isProd,sameSite:'strict'});res.json({ok:true});});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({email:req.admin.email}));
app.get('/api/admin/dashboard',adminAuth,async(_req,res)=>{
  try {
    const [stats,orders,products]=await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total_orders, COUNT(*) FILTER(WHERE status='Pending confirmation')::int AS pending_orders, COALESCE(SUM(total) FILTER(WHERE status NOT IN ('Cancelled')),0)::int AS gross_sales FROM orders`),
      pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 100'),
      pool.query('SELECT * FROM products ORDER BY id')
    ]);
    res.json({stats:stats.rows[0],orders:orders.rows,products:products.rows});
  }catch(e){console.error(e);res.status(500).json({error:'ড্যাশবোর্ড লোড হয়নি।'});}
});
app.patch('/api/admin/orders/:id',adminAuth,async(req,res)=>{
  const allowed=['Pending confirmation','Confirmed by phone','Processing','Shipped','Delivered','Cancelled'];
  if(!allowed.includes(req.body.status))return res.status(400).json({error:'অবৈধ অর্ডার স্ট্যাটাস।'});
  try{const r=await pool.query('UPDATE orders SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,status',[req.body.status,req.params.id]);if(!r.rowCount)return res.status(404).json({error:'অর্ডার পাওয়া যায়নি।'});res.json(r.rows[0]);}
  catch(e){console.error(e);res.status(500).json({error:'স্ট্যাটাস আপডেট হয়নি।'});}
});
app.post('/api/admin/products',adminAuth,async(req,res)=>{
  const {name,category,emoji='📦',price,compare_price=null,description='',stock=0}=req.body;
  if(!name||!category||!Number.isInteger(Number(price))||Number(price)<0)return res.status(400).json({error:'পণ্যের নাম, ক্যাটাগরি ও সঠিক দাম দিন।'});
  try{const r=await pool.query('INSERT INTO products(name,category,emoji,price,compare_price,description,stock) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[name,category,emoji,Number(price),compare_price?Number(compare_price):null,description,Math.max(0,Number(stock)||0)]);res.status(201).json(r.rows[0]);}
  catch(e){console.error(e);res.status(500).json({error:'পণ্য যোগ করা যায়নি।'});}
});
app.patch('/api/admin/products/:id',adminAuth,async(req,res)=>{
  const {name,category,emoji,price,compare_price,description,stock,active}=req.body;
  try{const r=await pool.query(`UPDATE products SET name=COALESCE($1,name),category=COALESCE($2,category),emoji=COALESCE($3,emoji),price=COALESCE($4,price),compare_price=$5,description=COALESCE($6,description),stock=COALESCE($7,stock),active=COALESCE($8,active) WHERE id=$9 RETURNING *`,[name,category,emoji,price==null?null:Number(price),compare_price==null?null:Number(compare_price),description,stock==null?null:Number(stock),active,req.params.id]);if(!r.rowCount)return res.status(404).json({error:'পণ্য পাওয়া যায়নি।'});res.json(r.rows[0]);}
  catch(e){console.error(e);res.status(500).json({error:'পণ্য আপডেট হয়নি।'});}
});
app.delete('/api/admin/products/:id',adminAuth,async(req,res)=>{try{const r=await pool.query('UPDATE products SET active=FALSE WHERE id=$1 RETURNING id',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'পণ্য পাওয়া যায়নি।'});res.json({ok:true});}catch(e){res.status(500).json({error:'পণ্য সরানো যায়নি।'});}});

app.get('/admin',(_req,res)=>res.sendFile(process.cwd()+'/public/admin.html'));
app.get('*',(req,res)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'API route পাওয়া যায়নি।'});res.sendFile(process.cwd()+'/public/index.html');});

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is required. Copy .env.example to .env and configure PostgreSQL.'); process.exit(1); }
if (isProd && (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)) { console.error('JWT_SECRET must be at least 32 characters in production.'); process.exit(1); }
initDb().then(()=>app.listen(PORT,()=>console.log(`ANIME BOX server listening on ${PORT}`))).catch(e=>{console.error('Database initialization failed:',e);process.exit(1);});
