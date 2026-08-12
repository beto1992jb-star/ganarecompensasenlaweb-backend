import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 5500;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_12345';
const CPX_APP_ID = process.env.CPX_APP_ID || '35135';
const MONETAG_DIRECT_LINK = 'https://omg10.com/4/11538152';

// --- MIDDLEWARES ---
app.use(cors());
app.use(express.json());

// --- BASE DE DATOS (PostgreSQL en Render) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ganarecompensas',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inicialización de tablas
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        referral_code VARCHAR(50) UNIQUE NOT NULL,
        referred_by VARCHAR(36),
        points_balance INT DEFAULT 0,
        country_code VARCHAR(5) DEFAULT 'AR',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS ad_sessions (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        created_at BIGINT NOT NULL,
        claimed INT DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS withdrawals (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        method VARCHAR(50) NOT NULL,
        account_details VARCHAR(255) NOT NULL,
        amount NUMERIC(10,2) NOT NULL,
        points_deducted INT NOT NULL,
        status VARCHAR(20) DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
    `);
    console.log("Tablas inicializadas correctamente.");
  } catch (err) {
    console.error("Error al inicializar la base de datos:", err);
  }
}
initDb();

// Función auxiliar para generar un código de referido único
async function generateUniqueReferralCode() {
  let isUnique = false;
  let code = '';
  let attempts = 0;

  while (!isUnique && attempts < 10) {
    code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const check = await pool.query('SELECT id FROM users WHERE referral_code = $1', [code]);
    if (check.rows.length === 0) {
      isUnique = true;
    }
    attempts++;
  }

  if (!isUnique) {
    code = uuidv4().substring(0, 8).toUpperCase();
  }

  return code;
}

// --- MIDDLEWARE DE AUTENTICACIÓN ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token de acceso no proporcionado.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado.' });
    req.user = user;
    next();
  });
}

function formatUser(user) {
  return {
    id: user.id,
    email: user.email,
    points_balance: parseInt(user.points_balance || 0, 10),
    referral_code: user.referral_code
  };
}

// --- RUTA RAÍZ DE PRUEBA ---
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    message: 'API de GanaRecompensas funcionando correctamente 🚀',
    endpoints: {
      register: 'POST /api/v1/auth/register',
      login: 'POST /api/v1/auth/login',
      profile: 'GET /api/v1/user/profile',
      startAd: 'POST /api/v1/ad/start',
      claimAd: 'POST /api/v1/ad/claim',
      withdraw: 'POST /api/v1/withdraw/request'
    }
  });
});

// --- RUTAS DE AUTENTICACIÓN ---

app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { email, password, referral_code, country_code } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos.' });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Verificación de existencia del usuario
    const existingUser = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado.' });
    }

    // Verificación opcional del código de referido recibido
    let referredByUserId = null;
    if (referral_code && typeof referral_code === 'string' && referral_code.trim() !== '') {
      const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referral_code.trim().toUpperCase()]);
      if (referrer.rows.length > 0) {
        referredByUserId = referrer.rows[0].id;
      }
    }

    const userId = uuidv4();
    const myReferralCode = await generateUniqueReferralCode();
    const hashedPassword = await bcrypt.hash(password, 10);
    const country = country_code || 'AR';

    // CORRECCIÓN: Se usa la columna password_hash en lugar de password
    const insertResult = await pool.query(
      `INSERT INTO users (id, email, password_hash, referral_code, referred_by, points_balance, country_code)
       VALUES ($1, $2, $3, $4, $5, 0, $6) RETURNING *`,
      [userId, cleanEmail, hashedPassword, myReferralCode, referredByUserId, country]
    );

    const newUser = insertResult.rows[0];
    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    return res.status(201).json({ 
      message: 'Registro exitoso.', 
      token, 
      user: formatUser(newUser) 
    });

  } catch (error) {
    console.error("Error detallado en registro:", error);
    
    if (error.code === '23505') {
      return res.status(400).json({ error: 'El correo o código ya se encuentra en uso.' });
    }
    
    return res.status(500).json({ error: 'Error interno en el servidor.' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    const user = result.rows[0];

    // CORRECCIÓN: Se compara el password ingresado contra user.password_hash
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(400).json({ error: 'Credenciales inválidas.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Inicio de sesión exitoso.', token, user: formatUser(user) });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: 'Error en servidor.' });
  }
});

app.post('/api/v1/auth/forgot-password', (req, res) => {
  res.json({ message: 'Si el correo existe, recibirás instrucciones.' });
});

// --- RUTAS DE USUARIO ---

app.get('/api/v1/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });
    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: 'Error al consultar perfil.' });
  }
});

// --- RUTAS DE ANUNCIOS MONETAG ---

app.post('/api/v1/ad/start', authenticateToken, async (req, res) => {
  try {
    const sessionId = uuidv4();
    const now = Date.now();
    await pool.query('INSERT INTO ad_sessions (id, user_id, created_at) VALUES ($1, $2, $3)', [sessionId, req.user.id, now]);

    res.json({ sessionId, adUrl: MONETAG_DIRECT_LINK, waitSeconds: 45 });
  } catch (err) {
    res.status(500).json({ error: 'Error al iniciar anuncio.' });
  }
});

app.post('/api/v1/ad/claim', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { sessionId } = req.body;
    const userId = req.user.id;

    const sessionRes = await client.query('SELECT * FROM ad_sessions WHERE id = $1 AND user_id = $2', [sessionId, userId]);
    const session = sessionRes.rows[0];

    if (!session) return res.status(404).json({ error: 'Sesión no válida.' });
    if (parseInt(session.claimed) === 1) return res.status(400).json({ error: 'Recompensa ya reclamada.' });

    const elapsedSeconds = (Date.now() - parseInt(session.created_at)) / 1000;
    if (elapsedSeconds < 40) return res.status(400).json({ error: 'Espere a que finalice el temporizador.' });

    const pointsAwarded = 10;

    await client.query('BEGIN');
    await client.query('UPDATE ad_sessions SET claimed = 1 WHERE id = $1', [sessionId]);
    await client.query('UPDATE users SET points_balance = points_balance + $1 WHERE id = $2', [pointsAwarded, userId]);

    const userRes = await client.query('SELECT referred_by FROM users WHERE id = $1', [userId]);
    if (userRes.rows[0] && userRes.rows[0].referred_by) {
      const commisionPoints = Math.floor(pointsAwarded * 0.03);
      if (commisionPoints > 0) {
        await client.query('UPDATE users SET points_balance = points_balance + $1 WHERE id = $2', [commisionPoints, userRes.rows[0].referred_by]);
      }
    }
    await client.query('COMMIT');

    res.json({ message: '¡Recompensa acreditada!', pointsAwarded });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Error al acreditar puntos.' });
  } finally {
    client.release();
  }
});

// --- RUTAS CPX Y RETIROS ---

app.get('/api/v1/cpx/survey-url', authenticateToken, (req, res) => {
  res.json({ url: `https://offers.cpx-research.com/index.php?app_id=${CPX_APP_ID}&ext_user_id=${req.user.id}` });
});

app.post('/api/v1/withdraw/request', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { method, payout_method, account_details, amount } = req.body;
    const withdrawalMethod = method || payout_method;
    const numAmount = parseFloat(amount);

    if (!withdrawalMethod || !account_details || isNaN(numAmount) || numAmount < 5.0) {
      return res.status(400).json({ error: 'Datos de retiro inválidos. Mínimo $5.00 USD.' });
    }

    const requiredPoints = Math.ceil(numAmount * 1000);
    const userRes = await client.query('SELECT points_balance FROM users WHERE id = $1', [req.user.id]);
    const currentPoints = parseInt(userRes.rows[0]?.points_balance || 0, 10);

    if (currentPoints < requiredPoints) {
      return res.status(400).json({ error: `Puntos insuficientes. Requiere ${requiredPoints} pts.` });
    }

    const withdrawId = uuidv4();

    await client.query('BEGIN');
    await client.query('UPDATE users SET points_balance = points_balance - $1 WHERE id = $2', [requiredPoints, req.user.id]);
    await client.query(
      `INSERT INTO withdrawals (id, user_id, method, account_details, amount, points_deducted)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [withdrawId, req.user.id, withdrawalMethod, account_details, numAmount, requiredPoints]
    );
    await client.query('COMMIT');

    res.json({ message: 'Solicitud enviada correctamente.', withdrawalId: withdrawId });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Error al procesar el retiro.' });
  } finally {
    client.release();
  }
});

app.listen(PORT, () => {
  console.log(`Servidor activo en el puerto ${PORT}`);
});
