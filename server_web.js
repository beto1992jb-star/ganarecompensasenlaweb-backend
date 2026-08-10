require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();

const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

const MONETAG_SDK_URL = process.env.MONETAG_SDK_URL || 'https://omg10.com/4/11538152';

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET es obligatorio.');
if (!ADMIN_SECRET || ADMIN_SECRET.length < 32) throw new Error('ADMIN_SECRET es obligatorio.');
if (!DATABASE_URL) throw new Error('DATABASE_URL es obligatorio.');
if (!CPX_HASH_SECRET || CPX_HASH_SECRET.length < 16) throw new Error('CPX_HASH_SECRET es obligatorio.');
if (!ALLOWED_ORIGIN) throw new Error('ALLOWED_ORIGIN es obligatorio.');

const GAME_REWARD_POINTS = 1;
const GAME_MIN_SECONDS = 60;
const REWARD_SESSION_MAX_AGE_MS = 30 * 60 * 1000;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim()).filter(Boolean);
app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Origen no permitido por CORS.'));
    },
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With', 'x-admin-secret'],
    optionsSuccessStatus: 204
}));

const db = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

function newRewardSessionId() { return crypto.randomBytes(32).toString('hex'); }
function isValidRewardSessionId(val) { return typeof val === 'string' && /^[a-f0-9]{64}$/.test(val); }
function safeRollback(client) { return client.query('ROLLBACK').catch(() => {}); }

async function ensureRewardTables() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS web_users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            country_code TEXT DEFAULT 'AR',
            tier_level INTEGER DEFAULT 1,
            points_balance INTEGER DEFAULT 0,
            referral_code TEXT UNIQUE,
            referred_by UUID REFERENCES web_users(id),
            total_referrals INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS reward_sessions (
            session_id TEXT PRIMARY KEY,
            user_id UUID NOT NULL,
            reward_type TEXT NOT NULL CHECK (reward_type IN ('video', 'game')),
            started_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            confirmed_at TIMESTAMPTZ NULL,
            claimed_at TIMESTAMPTZ NULL,
            points_awarded INTEGER DEFAULT 0
        );
    `);
}

// Creador automático de usuario de prueba si la BD está vacía
async function seedDefaultUser() {
    const testEmail = 'admin@ejemplo.com';
    const testPassword = 'Password123!';

    try {
        const userRes = await db.query('SELECT id FROM web_users WHERE email = $1', [testEmail]);
        if (userRes.rows.length === 0) {
            const hashedPassword = await bcrypt.hash(testPassword, 10);
            await db.query(
                `INSERT INTO web_users (email, password_hash) VALUES ($1, $2)`,
                [testEmail, hashedPassword]
            );
            console.log(`Usuario por defecto verificado/creado: ${testEmail}`);
        }
    } catch (e) {
        console.error('Error al poblar usuario por defecto:', e.message);
    }
}

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Token no provisto.' });
    try {
        const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET, { issuer: 'ganarecompensasenlaweb' });
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, error: 'Token inválido o expirado.' });
    }
};

// ==========================================
// AUTENTICACIÓN
// ==========================================

app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Correo y contraseña son obligatorios.' });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'La contraseña debe tener al menos 6 caracteres.' });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await db.query(
            `INSERT INTO web_users (email, password_hash) VALUES ($1, $2) RETURNING id, email, points_balance`,
            [normalizedEmail, hashedPassword]
        );

        const user = result.rows[0];
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' }
        );

        return res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente.',
            token,
            user: { id: user.id, email: user.email, pointsBalance: user.points_balance }
        });
    } catch (e) {
        if (e.code === '23505') {
            return res.status(409).json({ success: false, message: 'El correo electrónico ya está registrado.' });
        }
        console.error('Error en /auth/register:', e);
        return res.status(500).json({ success: false, message: 'Error interno al registrar usuario.' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Por favor, ingresa correo y contraseña.' });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();

        // Consulta SQL limpia contra web_users
        const userRes = await db.query('SELECT * FROM web_users WHERE email = $1', [normalizedEmail]);

        if (userRes.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }

        const user = userRes.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' }
        );

        return res.status(200).json({
            success: true,
            message: 'Inicio de sesión exitoso.',
            token,
            user: {
                id: user.id,
                email: user.email,
                pointsBalance: user.points_balance
            }
        });
    } catch (e) {
        console.error('Error en /auth/login:', e);
        return res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// ==========================================
// JUEGOS Y RECOMPENSAS
// ==========================================

app.post('/api/v1/game/start', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();

    try {
        await client.query('BEGIN');
        const sessionId = newRewardSessionId();
        const started = new Date();
        const expires = new Date(started.getTime() + REWARD_SESSION_MAX_AGE_MS);

        await client.query(
            `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at) VALUES ($1, $2, 'game', $3, $4)`,
            [sessionId, userId, started, expires]
        );

        await client.query('COMMIT');
        return res.json({ success: true, sessionId, adUrl: MONETAG_SDK_URL });
    } catch (e) {
        await safeRollback(client);
        console.error("Error en /game/start:", e);
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión de juego.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/game/claim', verifyToken, async (req, res) => {
    const { sessionId, adWatched } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) {
        return res.status(400).json({ success: false, error: 'Sesión inválida o malformada.' });
    }

    if (!adWatched) {
        return res.status(400).json({ success: false, error: 'Debes completar la interacción con el anuncio para monetizar.' });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const sRes = await client.query('SELECT * FROM reward_sessions WHERE session_id = $1 AND user_id = $2 FOR UPDATE', [sessionId, userId]);

        if (sRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'La sesión de juego no existe o expiró.' });
        }

        const session = sRes.rows[0];
        if (session.claimed_at) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Ya has reclamado esta recompensa.' });
        }

        const now = Date.now();
        const elapsedSeconds = Math.floor((now - new Date(session.started_at).getTime()) / 1000);

        if (elapsedSeconds < GAME_MIN_SECONDS) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Debes jugar al menos ${GAME_MIN_SECONDS} segundos. Llevas ${elapsedSeconds}s.` });
        }

        await client.query('UPDATE reward_sessions SET claimed_at = NOW(), points_awarded = $1 WHERE session_id = $2', [GAME_REWARD_POINTS, sessionId]);
        const balRes = await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2 RETURNING points_balance', [GAME_REWARD_POINTS, userId]);

        await client.query('COMMIT');
        return res.json({
            success: true,
            pointsAwarded: GAME_REWARD_POINTS,
            newBalance: balRes.rows[0].points_balance
        });
    } catch (e) {
        await safeRollback(client);
        console.error("Error en /game/claim:", e);
        return res.status(500).json({ success: false, error: 'Error interno al procesar el reclamo.' });
    } finally {
        client.release();
    }
});

app.get('*', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (require('fs').existsSync(indexPath)) return res.sendFile(indexPath);
    res.status(404).json({ success: false, error: 'Recurso no encontrado.' });
});

async function startServer() {
    await ensureRewardTables();
    await seedDefaultUser();
    app.listen(PORT, () => console.log(`Servidor activo en puerto ${PORT}`));
}
startServer();
