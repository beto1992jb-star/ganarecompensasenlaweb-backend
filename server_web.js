require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

const CPX_APP_ID = process.env.CPX_APP_ID || '35135';
const MONETAG_ZONE_ID = process.env.MONETAG_ZONE_ID || '11538152';
const MONETAG_SDK_URL = process.env.MONETAG_SDK_URL || 'https://omg10.com/4/11538152';
const MONETAG_SECRET = process.env.MONETAG_SECRET || '';

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET es obligatorio.');
if (!ADMIN_SECRET || ADMIN_SECRET.length < 32) throw new Error('ADMIN_SECRET es obligatorio.');
if (!DATABASE_URL) throw new Error('DATABASE_URL es obligatorio.');
if (!CPX_HASH_SECRET || CPX_HASH_SECRET.length < 16) throw new Error('CPX_HASH_SECRET es obligatorio.');
if (!ALLOWED_ORIGIN) throw new Error('ALLOWED_ORIGIN es obligatorio.');

const POINT_TO_CURRENCY_RATIO = 0.001; // 1000 Puntos = 1 USD
const GAME_REWARD_POINTS = 1;
const DEFAULT_VIDEO_FALLBACK_POINTS = 10; // Puntos por defecto en entorno de desarrollo/fallback
const REFERRAL_BONUS = 25;

const MAX_VIDEO_REWARDS_PER_DAY = 10;
const MAX_GAME_REWARDS_PER_DAY = 20;

const VIDEO_COOLDOWN_MS = 10 * 60 * 1000;
const GAME_COOLDOWN_MS = 60 * 1000;

const VIDEO_MIN_SECONDS = 10;
const GAME_MIN_SECONDS = 60;
const REWARD_SESSION_MAX_AGE_MS = 15 * 60 * 1000;

const PAYOUT_CONFIG = {
    binance: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.0 },
    mercadopago: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.15 },
    paypal: { minAmount: 5.00, fixedFeePercent: 0.015, fixedFeeAmount: 0.20 }
};

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

function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function normalizeCountryCode(code) { const v = String(code || 'AR').trim().toUpperCase(); return /^[A-Z]{2}$/.test(v) ? v : 'AR'; }
function newRewardSessionId() { return crypto.randomBytes(32).toString('hex'); }
function isValidUUID(val) { return typeof val === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(val); }
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

        CREATE TABLE IF NOT EXISTS reward_daily_usage (
            user_id UUID NOT NULL,
            reward_date DATE NOT NULL,
            video_count INTEGER NOT NULL DEFAULT 0,
            game_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, reward_date)
        );

        CREATE TABLE IF NOT EXISTS web_reward_events (
            id SERIAL PRIMARY KEY,
            user_id UUID NOT NULL,
            source_type TEXT NOT NULL,
            trans_id TEXT UNIQUE NOT NULL,
            points_awarded INTEGER NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS web_withdrawals (
            id SERIAL PRIMARY KEY,
            user_id UUID NOT NULL,
            amount_usd NUMERIC(10,2) NOT NULL,
            fee_usd NUMERIC(10,2) NOT NULL,
            net_amount_usd NUMERIC(10,2) NOT NULL,
            points_deducted INTEGER NOT NULL,
            payout_method TEXT NOT NULL,
            payout_destination TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
    `);
}

function createUserToken(user) {
    return jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' });
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

// --- AUTH ENDPOINTS ---
app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password, referral_code, country_code } = req.body || {};
    const normEmail = normalizeEmail(email);

    if (!isValidEmail(normEmail) || !password || password.length < 8) {
        return res.status(400).json({ success: false, error: 'Datos de registro inválidos.' });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const check = await client.query('SELECT id FROM web_users WHERE email = $1', [normEmail]);
        if (check.rows.length > 0) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'El correo ya está registrado.' });
        }

        let referrerId = null;
        if (referral_code) {
            const refCheck = await client.query('SELECT id FROM web_users WHERE referral_code = $1', [String(referral_code).toUpperCase().trim()]);
            if (refCheck.rows.length > 0) referrerId = refCheck.rows[0].id;
        }

        const myRefCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        const hash = await bcrypt.hash(password, 12);

        const newUser = await client.query(
            `INSERT INTO web_users (email, password_hash, country_code, referral_code, referred_by)
             VALUES ($1, $2, $3, $4, $5) RETURNING id, email, country_code, points_balance, referral_code`,
            [normEmail, hash, normalizeCountryCode(country_code), myRefCode, referrerId]
        );

        if (referrerId) {
            await client.query('UPDATE web_users SET points_balance = points_balance + $1, total_referrals = total_referrals + 1 WHERE id = $2', [REFERRAL_BONUS, referrerId]);
        }

        await client.query('COMMIT');
        const user = newUser.rows[0];
        return res.json({ success: true, user, token: createUserToken(user) });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al registrar.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    const normEmail = normalizeEmail(email);

    try {
        const userRes = await db.query('SELECT * FROM web_users WHERE email = $1', [normEmail]);
        if (userRes.rows.length === 0) return res.status(401).json({ success: false, error: 'Credenciales incorrectas.' });

        const user = userRes.rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ success: false, error: 'Credenciales incorrectas.' });

        delete user.password_hash;
        return res.json({ success: true, user, token: createUserToken(user) });
    } catch (err) {
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión.' });
    }
});

app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const userRes = await db.query('SELECT id, email, country_code, points_balance, referral_code FROM web_users WHERE id = $1', [req.user.userId]);
        if (userRes.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        return res.json({ success: true, user: userRes.rows[0] });
    } catch (e) {
        return res.status(500).json({ success: false, error: 'Error al consultar usuario.' });
    }
});

// --- MONETAG / VIDEO ENDPOINTS ---
const handleVideoStart = async (req, res) => {
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
        return res.json({
            success: true,
            sessionId,
            adUrl: `${MONETAG_SDK_URL}?subid=${sessionId}`
        });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al iniciar anuncio.' });
    } finally {
        client.release();
    }
};

const handleVideoClaim = async (req, res) => {
    const { sessionId } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) {
        return res.status(400).json({ success: false, error: 'ID de sesión inválido.' });
    }

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
            return res.status(409).json({ success: false, error: 'La recompensa ya fue acreditada.' });
        }

        let pointsToAward = Number(session.points_awarded) || 0;
        if (pointsToAward <= 0) {
            pointsToAward = DEFAULT_VIDEO_FALLBACK_POINTS; // Recompensa base
        }

        await client.query('UPDATE reward_sessions SET claimed_at = NOW(), points_awarded = $1 WHERE session_id = $2', [pointsToAward, sessionId]);
        const balRes = await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2 RETURNING points_balance', [pointsToAward, userId]);

        await client.query('COMMIT');
        return res.json({
            success: true,
            message: `¡Ganaste ${pointsToAward} puntos!`,
            pointsAwarded: pointsToAward,
            newBalance: balRes.rows[0].points_balance
        });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al solicitar acreditación.' });
    } finally {
        client.release();
    }
};

app.post('/api/v1/ad/start', verifyToken, handleVideoStart);
app.post('/api/v1/web-video/start', verifyToken, handleVideoStart);

app.post('/api/v1/ad/claim', verifyToken, handleVideoClaim);
app.post('/api/v1/web-video/claim', verifyToken, handleVideoClaim);

// --- GAME ENDPOINTS ---
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
        return res.status(500).json({ success: false, error: 'Error al iniciar juego.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/game/claim', verifyToken, async (req, res) => {
    const { sessionId } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) {
        return res.status(400).json({ success: false, error: 'Sesión inválida.' });
    }

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
            return res.status(409).json({ success: false, error: 'Ya has reclamado estos puntos.' });
        }

        const now = Date.now();
        if (now < new Date(session.started_at).getTime() + GAME_MIN_SECONDS * 1000) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Debes interactuar al menos ${GAME_MIN_SECONDS} segundos.` });
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
        return res.status(500).json({ success: false, error: 'Error al procesar reclamo.' });
    } finally {
        client.release();
    }
});

// --- WITHDRAWALS ---
app.post('/api/v1/withdraw/request', verifyToken, async (req, res) => {
    const { amount, method, details } = req.body || {};
    const userId = req.user.userId;
    const numericAmount = Number(amount);

    if (!numericAmount || numericAmount < 5.0) {
        return res.status(400).json({ success: false, error: 'Monto mínimo de retiro: $5.00 USD.' });
    }

    const requiredPoints = Math.round(numericAmount / POINT_TO_CURRENCY_RATIO);
    const client = await db.connect();

    try {
        await client.query('BEGIN');
        const uRes = await client.query('SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE', [userId]);

        if (uRes.rows[0].points_balance < requiredPoints) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'Saldo de puntos insuficiente.' });
        }

        await client.query('UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2', [requiredPoints, userId]);
        await client.query(
            `INSERT INTO web_withdrawals (user_id, amount_usd, fee_usd, net_amount_usd, points_deducted, payout_method, payout_destination)
             VALUES ($1, $2, 0, $2, $3, $4, $5)`,
            [userId, numericAmount, requiredPoints, method, details]
        );

        await client.query('COMMIT');
        return res.json({ success: true, message: 'Solicitud de retiro registrada con éxito.' });
    } catch (e) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al procesar retiro.' });
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
    app.listen(PORT, () => console.log(`Servidor activo en el puerto ${PORT}`));
}
startServer();
