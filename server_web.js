require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

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
const AD_REWARD_POINTS = 5;
const GAME_MIN_SECONDS = 60; // 60 segundos de espera obligatoria
const REWARD_SESSION_MAX_AGE_MS = 30 * 60 * 1000; // 30 minutos de tolerancia

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
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
function hashPassword(password) { return crypto.pbkdf2Sync(password, JWT_SECRET, 1000, 64, 'sha512').toString('hex'); }

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

        CREATE TABLE IF NOT EXISTS withdrawals (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES web_users(id),
            method TEXT NOT NULL,
            account_details TEXT NOT NULL,
            amount_usd NUMERIC(10,2) NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    `);
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

// --- ENDPOINTS AUTENTICACIÓN ---
app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password, referral_code, country_code } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email y contraseña requeridos.' });

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const passHash = hashPassword(password);
        const myRefCode = crypto.randomBytes(4).toString('hex').toUpperCase();

        let referredBy = null;
        if (referral_code) {
            const refRes = await client.query('SELECT id FROM web_users WHERE referral_code = $1', [referral_code]);
            if (refRes.rows.length > 0) referredBy = refRes.rows[0].id;
        }

        const userRes = await client.query(
            `INSERT INTO web_users (email, password_hash, country_code, referral_code, referred_by)
             VALUES ($1, $2, $3, $4, $5) RETURNING id, email, points_balance, referral_code`,
            [email.toLowerCase(), passHash, country_code || 'AR', myRefCode, referredBy]
        );

        if (referredBy) {
            await client.query('UPDATE web_users SET total_referrals = total_referrals + 1 WHERE id = $1', [referredBy]);
        }

        await client.query('COMMIT');
        const user = userRes.rows[0];
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' });

        return res.json({ success: true, user: { id: user.id, email: user.email, points_balance: user.points_balance, my_referral_code: user.referral_code }, token });
    } catch (e) {
        await safeRollback(client);
        if (e.code === '23505') return res.status(400).json({ success: false, error: 'El correo electrónico ya está registrado.' });
        return res.status(500).json({ success: false, error: 'Error al registrar usuario.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email y contraseña requeridos.' });

    try {
        const passHash = hashPassword(password);
        const userRes = await db.query('SELECT * FROM web_users WHERE email = $1 AND password_hash = $2', [email.toLowerCase(), passHash]);

        if (userRes.rows.length === 0) return res.status(401).json({ success: false, error: 'Credenciales inválidas.' });

        const user = userRes.rows[0];
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' });

        return res.json({
            success: true,
            user: { id: user.id, email: user.email, points_balance: user.points_balance, my_referral_code: user.referral_code },
            token
        });
    } catch (e) {
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión.' });
    }
});

app.post('/api/v1/auth/forgot-password', (req, res) => {
    return res.json({ success: true, message: 'Si el correo existe, recibirás instrucciones para restablecer tu contraseña.' });
});

app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const userRes = await db.query('SELECT id, email, points_balance, referral_code FROM web_users WHERE id = $1', [req.user.userId]);
        if (userRes.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        const user = userRes.rows[0];
        return res.json({ success: true, user: { id: user.id, email: user.email, points_balance: user.points_balance, my_referral_code: user.referral_code } });
    } catch (e) {
        return res.status(500).json({ success: false, error: 'Error al consultar datos.' });
    }
});

// --- ENDPOINTS ANUNCIOS DIRECTOS ---
app.post('/api/v1/ad/start', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const sessionId = newRewardSessionId();
        const started = new Date();
        const expires = new Date(started.getTime() + REWARD_SESSION_MAX_AGE_MS);

        await client.query(
            `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at) VALUES ($1, $2, 'video', $3, $4)`,
            [sessionId, userId, started, expires]
        );

        await client.query('COMMIT');
        return res.json({ success: true, sessionId, adUrl: MONETAG_SDK_URL });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al iniciar anuncio.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/ad/claim', verifyToken, async (req, res) => {
    const { sessionId } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) return res.status(400).json({ success: false, error: 'Sesión inválida.' });

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const sRes = await client.query('SELECT * FROM reward_sessions WHERE session_id = $1 AND user_id = $2 FOR UPDATE', [sessionId, userId]);

        if (sRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Sesión no encontrada.' });
        }

        const session = sRes.rows[0];
        if (session.claimed_at) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Esta recompensa ya fue reclamada.' });
        }

        await client.query('UPDATE reward_sessions SET claimed_at = NOW(), points_awarded = $1 WHERE session_id = $2', [AD_REWARD_POINTS, sessionId]);
        const balRes = await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2 RETURNING points_balance', [AD_REWARD_POINTS, userId]);

        // Comisión por referido (3%)
        const uRes = await client.query('SELECT referred_by FROM web_users WHERE id = $1', [userId]);
        if (uRes.rows[0] && uRes.rows[0].referred_by) {
            const refPoints = Math.max(1, Math.round(AD_REWARD_POINTS * 0.03));
            await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2', [refPoints, uRes.rows[0].referred_by]);
        }

        await client.query('COMMIT');
        return res.json({ success: true, message: 'Puntos acreditados con éxito.', newBalance: balRes.rows[0].points_balance });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al validar anuncio.' });
    } finally {
        client.release();
    }
});

// --- ENDPOINTS JUEGOS ---
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

// --- ENDPOINTS SOLICITUD DE RETIRO ---
app.post('/api/v1/withdraw/request', verifyToken, async (req, res) => {
    const { method, details, amount } = req.body || {};
    const userId = req.user.userId;

    if (!method || !details || !amount || amount < 5) {
        return res.status(400).json({ success: false, error: 'El retiro mínimo es de $5.00 USD y todos los campos son obligatorios.' });
    }

    const pointsNeeded = amount * 1000;
    const client = await db.connect();

    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE', [userId]);
        const balance = userRes.rows[0]?.points_balance || 0;

        if (balance < pointsNeeded) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Saldo insuficiente. Requiere ${pointsNeeded} puntos.` });
        }

        await client.query('UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2', [pointsNeeded, userId]);
        await client.query(
            'INSERT INTO withdrawals (user_id, method, account_details, amount_usd) VALUES ($1, $2, $3, $4)',
            [userId, method, details, amount]
        );

        await client.query('COMMIT');
        return res.json({ success: true, message: 'Solicitud de retiro registrada exitosamente.' });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al procesar la solicitud de retiro.' });
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
    app.listen(PORT, () => console.log(`Servidor activo en puerto ${PORT}`));
}
startServer();
