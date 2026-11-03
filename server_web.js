import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 5500;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_12345';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ganarecompensasenlaweb.netlify.app';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'mi_clave_secreta_admin_123';

const CPX_APP_ID = process.env.CPX_APP_ID || '35135';
const AYET_APP_ID = process.env.AYET_APP_ID || '24629';
const DIRECT_LINK_URL = process.env.DIRECT_LINK_URL || 'https://omg10.com/4/11538152';
const POSTBACK_SECRET = process.env.POSTBACK_SECRET || process.env.CPX_HASH_SECRET;

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' }
});

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-secret'] }));
app.options('*', cors());
app.use(express.json());

app.get('/', (req, res) => res.status(200).send('API funcionando 🚀'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ganarecompensas',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function checkAndExecuteWeeklyReset() {
  const client = await pool.connect();
  try {
    const ahora = new Date();
    const startOfYear = new Date(ahora.getUTCFullYear(), 0, 1);
    const numSemanaUtc = Math.ceil((((ahora - startOfYear) / 86400000) + startOfYear.getDay() + 1) / 7);
    if (ahora.getUTCDay() !== 1) return; 

    const res = await client.query('SELECT current_week FROM system_state LIMIT 1');
    if (res.rows[0]?.current_week !== numSemanaUtc) {
      await client.query('BEGIN');
      const winnersRes = await client.query('SELECT id, arcade_level FROM users ORDER BY arcade_level DESC LIMIT 3');
      const winnerPoints = [100, 60, 40]; 
      for (let i = 0; i < winnersRes.rows.length; i++) {
        if (winnersRes.rows[i] && winnersRes.rows[i].arcade_level > 1) {
          await client.query('UPDATE users SET points_balance = points_balance + $1 WHERE id = $2', [winnerPoints[i], winnersRes.rows[i].id]);
        }
      }
      await client.query('UPDATE users SET arcade_level = 1, reaction_level = 1, attention_level = 1');
      await client.query('UPDATE system_state SET current_week = $1', [numSemanaUtc]);
      await client.query('COMMIT');
    }
  } catch (err) { await client.query('ROLLBACK'); } finally { client.release(); }
}

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        referral_code VARCHAR(50) UNIQUE NOT NULL,
        referred_by VARCHAR(36),
        points_balance NUMERIC(10,2) DEFAULT 0.00,
        arcade_level INT DEFAULT 1,
        reaction_level INT DEFAULT 1,
        attention_level INT DEFAULT 1,
        reset_token VARCHAR(255),
        reset_token_expires BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await client.query(`CREATE TABLE IF NOT EXISTS ad_sessions (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, created_at BIGINT NOT NULL, claimed INT DEFAULT 0);`);
    await client.query(`CREATE TABLE IF NOT EXISTS withdrawals (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, method VARCHAR(50) NOT NULL, account_details VARCHAR(255) NOT NULL, amount NUMERIC(10,2) NOT NULL, points_deducted INT NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS system_state (id INT PRIMARY KEY, current_week INT NOT NULL DEFAULT 0, last_reset_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`INSERT INTO system_state (id, current_week, last_reset_date) SELECT 1, 0, CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM system_state)`);
    await client.query('COMMIT');
  } catch (err) { await client.query('ROLLBACK'); } finally { client.release(); }
}

(async () => { await initDb(); await checkAndExecuteWeeklyReset(); })();

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido.' });
    req.user = user;
    next();
  });
}

function formatUser(user) {
  return {
    id: user.id, email: user.email,
    points_balance: parseFloat(user.points_balance || 0),
    referral_code: user.referral_code,
    arcade_level: parseInt(user.arcade_level || 1, 10),
    reaction_level: parseInt(user.reaction_level || 1, 10),
    attention_level: parseInt(user.attention_level || 1, 10)
  };
}

app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { email, password, referral_code } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'El correo ya existe.' });
    
    let refId = null;
    if (referral_code) {
      const ref = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referral_code.toUpperCase()]);
      if (ref.rows.length > 0) refId = ref.rows[0].id;
    }

    const userId = uuidv4();
    const myCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (id, email, password, referral_code, referred_by, points_balance, arcade_level, reaction_level, attention_level) VALUES ($1, $2, $3, $4, $5, 0, 1, 1, 1) RETURNING *`,
      [userId, cleanEmail, hashedPassword, myCode, refId]
    );
    const token = jwt.sign({ id: userId, email: cleanEmail }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Registro exitoso.', token, user: formatUser(result.rows[0]) });
  } catch (err) { res.status(500).json({ error: 'Error en servidor.' }); }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = $1', [email.trim().toLowerCase()]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Credenciales inválidas.' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login exitoso.', token, user: formatUser(user) });
  } catch (err) { res.status(500).json({ error: 'Error en servidor.' }); }
});

app.get('/api/v1/user/profile', authenticateToken, async (req, res) => {
  await checkAndExecuteWeeklyReset();
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  res.json({ user: formatUser(result.rows[0]) });
});

app.post('/api/v1/ad/start', authenticateToken, async (req, res) => {
  const points = parseFloat(req.body.points || 1.00);
  await pool.query('UPDATE users SET points_balance = points_balance + $1 WHERE id = $2', [points, req.user.id]);
  res.json({ sessionId: uuidv4(), adUrl: `${DIRECT_LINK_URL}?sub1=${req.user.id}` });
});

app.post('/api/v1/user/arcade-level', authenticateToken, async (req, res) => {
  await pool.query('UPDATE users SET arcade_level = GREATEST(COALESCE(arcade_level, 1), $1) WHERE id = $2', [parseInt(req.body.level, 10), req.user.id]);
  res.json({ success: true });
});

app.post('/api/v1/user/reaction-level', authenticateToken, async (req, res) => {
  await pool.query('UPDATE users SET reaction_level = GREATEST(COALESCE(reaction_level, 1), $1) WHERE id = $2', [parseInt(req.body.level, 10), req.user.id]);
  res.json({ success: true });
});

app.post('/api/v1/user/attention-level', authenticateToken, async (req, res) => {
  await pool.query('UPDATE users SET attention_level = GREATEST(COALESCE(attention_level, 1), $1) WHERE id = $2', [parseInt(req.body.level, 10), req.user.id]);
  res.json({ success: true });
});

app.get('/api/v1/leaderboards', async (req, res) => {
  await checkAndExecuteWeeklyReset();
  const formatList = (rows) => rows.map((row, index) => {
    const parts = row.email.split('@');
    return { position: index + 1, email: `${parts[0].substring(0, 4)}****@${parts[1]}`, level: row.val };
  });

  const arcade = await pool.query('SELECT email, arcade_level AS val FROM users WHERE arcade_level > 1 ORDER BY arcade_level DESC LIMIT 10');
  const reaction = await pool.query('SELECT email, reaction_level AS val FROM users WHERE reaction_level > 1 ORDER BY reaction_level DESC LIMIT 10');
  const attention = await pool.query('SELECT email, attention_level AS val FROM users WHERE attention_level > 1 ORDER BY attention_level DESC LIMIT 10');

  res.json({
    success: true,
    arcade: formatList(arcade.rows),
    reaction: formatList(reaction.rows),
    attention: formatList(attention.rows)
  });
});

app.post('/api/v1/withdraw/request', authenticateToken, async (req, res) => {
  const { method, account_details, amount } = req.body;
  const reqPts = Math.ceil(parseFloat(amount) * 1000);
  const u = await pool.query('SELECT points_balance FROM users WHERE id = $1', [req.user.id]);
  if (parseFloat(u.rows[0].points_balance) < reqPts) return res.status(400).json({ error: 'Saldo insuficiente.' });

  await pool.query('BEGIN');
  await pool.query('UPDATE users SET points_balance = points_balance - $1 WHERE id = $2', [reqPts, req.user.id]);
  await pool.query('INSERT INTO withdrawals (id, user_id, method, account_details, amount, points_deducted) VALUES ($1, $2, $3, $4, $5, $6)', [uuidv4(), req.user.id, method, account_details, amount, reqPts]);
  await pool.query('COMMIT');
  res.json({ message: 'Retiro solicitado.' });
});

app.listen(PORT, () => console.log(`🚀 Servidor activo en puerto ${PORT}`));
