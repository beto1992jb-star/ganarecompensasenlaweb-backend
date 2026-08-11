import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 5500;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_12345';
const CPX_APP_ID = process.env.CPX_APP_ID || '35135';
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET || 'tu_cpx_hash_secret';
const MONETAG_DIRECT_LINK = 'https://omg10.com/4/11538152';

// --- MIDDLEWARES ---
app.use(cors());
app.use(express.json());

// --- BASE DE DATOS (SQLite) ---
const db = new Database('database.db');

// Inicialización de tablas
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    referral_code TEXT UNIQUE NOT NULL,
    referred_by TEXT,
    points_balance INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS ad_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    claimed INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    method TEXT NOT NULL,
    account_details TEXT NOT NULL,
    amount REAL NOT NULL,
    points_deducted INTEGER NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// --- MIDDLEWARE DE AUTENTICACIÓN ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso no proporcionado.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
    req.user = user;
    next();
  });
}

// Auxiliar para formatear objeto de usuario público
function formatUser(user) {
  return {
    id: user.id,
    email: user.email,
    points_balance: user.points_balance,
    referral_code: user.referral_code
  };
}

// --- RUTAS DE AUTENTICACIÓN ---

// Registro
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { email, password, referral_code } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
    }

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'El correo electrónico ya está registrado.' });
    }

    let referredByUserId = null;
    if (referral_code) {
      const referrer = db.prepare('SELECT id FROM users WHERE referral_code = ?').get(referral_code.toUpperCase());
      if (referrer) {
        referredByUserId = referrer.id;
      }
    }

    const userId = uuidv4();
    const myReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    const hashedPassword = await bcrypt.hash(password, 10);

    db.prepare(`
      INSERT INTO users (id, email, password, referral_code, referred_by, points_balance)
      VALUES (?, ?, ?, ?, ?, 0)
    `).run(userId, email, hashedPassword, myReferralCode, referredByUserId);

    const newUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Usuario registrado exitosamente.',
      token,
      user: formatUser(newUser)
    });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Login
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Inicio de sesión exitoso.',
      token,
      user: formatUser(user)
    });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Recuperar Contraseña
app.post('/api/v1/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Se requiere el correo electrónico.' });
  }
  
  // Aquí se integraría un servicio de envío de correos (ej. Nodemailer / SendGrid)
  res.json({ message: 'Si el correo existe en la plataforma, recibirás instrucciones de restablecimiento.' });
});

// --- RUTAS DE USUARIO ---

// Perfil de Usuario
app.get('/api/v1/user/profile', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(444).json({ error: 'Usuario no encontrado.' });
  }
  res.json({ user: formatUser(user) });
});

// --- RUTAS DE ANUNCIOS MONETAG ---

// Iniciar sesión de anuncio
app.post('/api/v1/ad/start', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const sessionId = uuidv4();
  const now = Date.now();

  db.prepare('INSERT INTO ad_sessions (id, user_id, created_at) VALUES (?, ?, ?)').run(sessionId, userId, now);

  res.json({
    sessionId,
    adUrl: MONETAG_DIRECT_LINK,
    waitSeconds: 45
  });
});

// Reclamar puntos por anuncio visto
app.post('/api/v1/ad/claim', authenticateToken, (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.id;

  if (!sessionId) {
    return res.status(400).json({ error: 'sessionId es requerido.' });
  }

  const session = db.prepare('SELECT * FROM ad_sessions WHERE id = ? AND user_id = ?').get(sessionId, userId);

  if (!session) {
    return res.status(404).json({ error: 'Sesión de anuncio no válida.' });
  }

  if (session.claimed === 1) {
    return res.status(400).json({ error: 'Esta recompensa ya fue acreditada.' });
  }

  const elapsedSeconds = (Date.now() - session.created_at) / 1000;
  if (elapsedSeconds < 40) { // Margen de gracia sobre los 45 segundos
    return res.status(400).json({ error: 'Debes esperar a que el temporizador complete antes de reclamar.' });
  }

  const pointsAwarded = 10;

  // Transacción para acreditar puntos al usuario y comisión al referido
  const processReward = db.transaction(() => {
    // Marcar sesión como reclamada
    db.prepare('UPDATE ad_sessions SET claimed = 1 WHERE id = ?').run(sessionId);

    // Sumar puntos al usuario
    db.prepare('UPDATE users SET points_balance = points_balance + ? WHERE id = ?').run(pointsAwarded, userId);

    // Calcular y asignar comisión de referido (3%)
    const user = db.prepare('SELECT referred_by FROM users WHERE id = ?').get(userId);
    if (user && user.referred_by) {
      const commisionPoints = Math.floor(pointsAwarded * 0.03);
      if (commisionPoints > 0) {
        db.prepare('UPDATE users SET points_balance = points_balance + ? WHERE id = ?').run(commisionPoints, user.referred_by);
      }
    }
  });

  processReward();

  res.json({
    message: 'Recompensa acreditada exitosamente.',
    pointsAwarded
  });
});

// --- RUTAS DE CPX RESEARCH ---

// Obtener URL parametrizada para CPX Research
app.get('/api/v1/cpx/survey-url', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const url = `https://offers.cpx-research.com/index.php?app_id=${CPX_APP_ID}&ext_user_id=${userId}`;
  res.json({ url });
});

// Postback Callback de CPX Research (Notificaciones Servidor a Servidor)
app.get('/api/v1/cpx/postback', (req, res) => {
  const { status, trans_id, status_code, amount_local, ext_user_id, hash } = req.query;

  // Validación básica del Postback
  if (!ext_user_id || !amount_local) {
    return res.status(400).send('Missing parameters');
  }

  const points = parseInt(amount_local, 10);

  if (status === '1' || status_code === '1') { // 1 suele indicar éxito en CPX
    const user = db.prepare('SELECT id, referred_by FROM users WHERE id = ?').get(ext_user_id);
    if (user) {
      db.prepare('UPDATE users SET points_balance = points_balance + ? WHERE id = ?').run(points, user.id);

      // Comisión al referidor (3%)
      if (user.referred_by) {
        const commision = Math.floor(points * 0.03);
        if (commision > 0) {
          db.prepare('UPDATE users SET points_balance = points_balance + ? WHERE id = ?').run(commision, user.referred_by);
        }
      }
    }
  }

  res.send('OK');
});

// --- RUTAS DE RETIRAR SALDO ---

app.post('/api/v1/withdraw/request', authenticateToken, (req, res) => {
  const { method, payout_method, account_details, amount } = req.body;
  const userId = req.user.id;

  const withdrawalMethod = method || payout_method;
  const numAmount = parseFloat(amount);

  if (!withdrawalMethod || !account_details || isNaN(numAmount)) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  if (numAmount < 5.0) {
    return res.status(400).json({ error: 'El retiro mínimo es de $5.00 USD.' });
  }

  // Conversión: 1000 puntos = $1.00 USD
  const requiredPoints = Math.ceil(numAmount * 1000);

  const user = db.prepare('SELECT points_balance FROM users WHERE id = ?').get(userId);

  if (!user || user.points_balance < requiredPoints) {
    return res.status(400).json({ error: `Saldo insuficiente. Necesitas al menos ${requiredPoints} pts para retirar $${numAmount.toFixed(2)} USD.` });
  }

  const withdrawId = uuidv4();

  const processWithdrawal = db.transaction(() => {
    // Deducir saldo
    db.prepare('UPDATE users SET points_balance = points_balance - ? WHERE id = ?').run(requiredPoints, userId);

    // Registrar solicitud
    db.prepare(`
      INSERT INTO withdrawals (id, user_id, method, account_details, amount, points_deducted)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(withdrawId, userId, withdrawalMethod, account_details, numAmount, requiredPoints);
  });

  processWithdrawal();

  res.json({
    message: 'Solicitud de retiro procesada correctamente.',
    withdrawalId: withdrawId
  });
});

// --- INICIO DEL SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor de GanaRecompensas corriendo en http://localhost:${PORT}`);
});
