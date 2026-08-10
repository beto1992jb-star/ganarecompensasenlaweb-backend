require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// CONFIGURACIÓN DE PUERTO Y VARIABLES DE ENTORNO
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

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET debe tener al menos 32 caracteres.');
if (!ADMIN_SECRET || ADMIN_SECRET.length < 32) throw new Error('ADMIN_SECRET debe tener al menos 32 caracteres.');
if (!DATABASE_URL) throw new Error('DATABASE_URL es obligatorio.');
if (!CPX_HASH_SECRET || CPX_HASH_SECRET.length < 16) throw new Error('CPX_HASH_SECRET es obligatorio.');
if (!ALLOWED_ORIGIN) throw new Error('ALLOWED_ORIGIN es obligatorio.');

// CONSTANTES DE NEGOCIO
const POINT_TO_CURRENCY_RATIO = 0.001; // 1000 pts = $1.00 USD
const VIDEO_REWARD_POINTS = 10;
const GAME_REWARD_POINTS = 1;
const REFERRAL_BONUS = 25;

const MAX_VIDEO_REWARDS_PER_DAY = 10;
const MAX_GAME_REWARDS_PER_DAY = 30;

const VIDEO_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutos
const GAME_COOLDOWN_MS = 60 * 1000;       // 1 minuto

const VIDEO_MIN_SECONDS = 45;
const GAME_MIN_SECONDS = 60;

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
    credentials: false
}));

// BASE DE DATOS
const db = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

// FUNCIONES AUXILIARES
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function normalizeCountryCode(cc) { const v = String(cc || 'AR').trim().toUpperCase(); return /^[A-Z]{2}$/.test(v) ? v : 'AR'; }
function newRewardSessionId() { return crypto.randomBytes(32).toString('hex'); }
function isValidUUID(val) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(val); }
function isValidRewardSessionId(val) { return /^[a-f0-9]{64}$/.test(val); }
function safeRollback(client) { return client.query('ROLLBACK').catch(() => {}); }

async function insertRewardEvent(client, { userId, sourceType, transId, points }) {
    const res = await client.query(
        `INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded)
         VALUES ($1, $2, $3, $4) ON CONFLICT (trans_id) DO NOTHING RETURNING id`,
        [userId, sourceType, transId, points]
    );
    return res.rows.length > 0;
}

// INICIALIZACIÓN DE TABLAS
async function initDB() {
    await db.query(`
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        CREATE TABLE IF NOT EXISTS web_users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            country_code VARCHAR(10) DEFAULT 'AR',
            points_balance NUMERIC(12, 2) DEFAULT 0,
            referral_code VARCHAR(50) UNIQUE NOT NULL,
            referred_by UUID REFERENCES web_users(id),
            total_referrals INTEGER DEFAULT 0,
            tier_level INTEGER DEFAULT 1,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS web_reward_events (
            id SERIAL PRIMARY KEY,
            user_id UUID REFERENCES web_users(id),
            source_type VARCHAR(50) NOT NULL,
            trans_id VARCHAR(255) UNIQUE NOT NULL,
            points_awarded NUMERIC(12, 2) NOT NULL,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS web_withdrawals (
            id SERIAL PRIMARY KEY,
            user_id UUID REFERENCES web_users(id),
            amount_usd NUMERIC(10, 2) NOT NULL,
            fee_usd NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
            net_amount_usd NUMERIC(10, 2) NOT NULL,
            points_deducted NUMERIC(12, 2) NOT NULL,
            payout_method VARCHAR(50) NOT NULL,
            payout_destination TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reward_sessions (
            session_id TEXT PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES web_users(id),
            reward_type TEXT NOT NULL CHECK (reward_type IN ('video', 'game')),
            started_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            confirmed_at TIMESTAMPTZ NULL,
            claimed_at TIMESTAMPTZ NULL,
            points_awarded INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS reward_daily_usage (
            user_id UUID NOT NULL REFERENCES web_users(id),
            reward_date DATE NOT NULL,
            video_count INTEGER NOT NULL DEFAULT 0,
            game_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, reward_date)
        );
    `);
}

initDB().catch(err => console.error("Error inicializando DB:", err));

// AUTENTICACIÓN
function createUserToken(user) {
    return jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' });
}

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Acceso denegado.' });
    }
    try {
        const decoded = jwt.verify(authHeader.slice(7).trim(), JWT_SECRET, { issuer: 'ganarecompensasenlaweb' });
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ success: false, error: 'Token inválido o expirado.' });
    }
};

// RUTAS AUTH
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
            const refRes = await client.query('SELECT id FROM web_users WHERE referral_code = $1', [String(referral_code).trim().toUpperCase()]);
            if (refRes.rows.length > 0) referrerId = refRes.rows[0].id;
        }

        const myRefCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        const passHash = await bcrypt.hash(password, 10);

        const newUser = await client.query(
            `INSERT INTO web_users (email, password_hash, country_code, referral_code, referred_by)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, email, country_code, tier_level, points_balance, referral_code, total_referrals`,
            [normEmail, passHash, normalizeCountryCode(country_code), myRefCode, referrerId]
        );

        const user = newUser.rows[0];
        if (referrerId) {
            const transId = `REF_${user.id}_${Date.now()}`;
            if (await insertRewardEvent(client, { userId: referrerId, sourceType: 'REFERRAL_BONUS', transId, points: REFERRAL_BONUS })) {
                await client.query('UPDATE web_users SET points_balance = points_balance + $1, total_referrals = total_referrals + 1 WHERE id = $2', [REFERRAL_BONUS, referrerId]);
            }
        }

        await client.query('COMMIT');
        return res.json({ success: true, user, token: createUserToken(user) });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error en registro.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    const normEmail = normalizeEmail(email);
    try {
        const uRes = await db.query('SELECT * FROM web_users WHERE email = $1', [normEmail]);
        if (uRes.rows.length === 0) return res.status(401).json({ success: false, error: 'Credenciales inválidas.' });

        const user = uRes.rows[0];
        if (!await bcrypt.compare(password, user.password_hash)) {
            return res.status(401).json({ success: false, error: 'Credenciales inválidas.' });
        }

        delete user.password_hash;
        return res.json({ success: true, user, token: createUserToken(user) });
    } catch (err) {
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión.' });
    }
});

app.post('/api/v1/auth/forgot-password', (req, res) => {
    return res.json({ success: true, message: 'Si el correo existe, recibirás instrucciones.' });
});

app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const uRes = await db.query('SELECT id, email, country_code, tier_level, points_balance, referral_code, total_referrals FROM web_users WHERE id = $1', [req.user.userId]);
        if (uRes.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        return res.json({ success: true, user: uRes.rows[0] });
    } catch (err) {
        return res.status(500).json({ success: false, error: 'Error al consultar perfil.' });
    }
});

// RUTAS DE ANUNCIOS Y JUEGOS
app.post('/api/v1/ad/start', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const sessionId = newRewardSessionId();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        await client.query(
            `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at)
             VALUES ($1, $2, 'video', NOW(), $3)`,
            [sessionId, userId, expiresAt]
        );

        await client.query('COMMIT');
        return res.json({ success: true, sessionId, adUrl: MONETAG_SDK_URL, waitSeconds: VIDEO_MIN_SECONDS });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al iniciar anuncio.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/ad/claim', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { sessionId } = req.body || {};
    if (!sessionId) return res.status(400).json({ success: false, error: 'sessionId requerido.' });

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
            return res.status(400).json({ success: false, error: 'Recompensa ya reclamada.' });
        }

        const elapsed = (Date.now() - new Date(session.started_at).getTime()) / 1000;
        if (elapsed < VIDEO_MIN_SECONDS) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Debes esperar al menos ${VIDEO_MIN_SECONDS} segundos.` });
        }

        const pts = session.points_awarded > 0 ? session.points_awarded : VIDEO_REWARD_POINTS;
        const transId = `VID_${sessionId}`;

        await client.query('UPDATE reward_sessions SET claimed_at = NOW() WHERE session_id = $1', [sessionId]);
        if (await insertRewardEvent(client, { userId, sourceType: 'MONETAG_AD', transId, points: pts })) {
            await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2', [pts, userId]);
        }

        await client.query('COMMIT');
        return res.json({ success: true, message: '¡Puntos acreditados con éxito!', pointsAwarded: pts });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al acreditar puntos.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/game/start', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const active = await client.query(
            `SELECT session_id, started_at FROM reward_sessions 
             WHERE user_id = $1 AND reward_type = 'game' AND claimed_at IS NULL AND expires_at > NOW() 
             ORDER BY started_at DESC LIMIT 1`,
            [userId]
        );

        if (active.rows.length > 0) {
            const elapsed = Math.floor((Date.now() - new Date(active.rows[0].started_at).getTime()) / 1000);
            const remaining = Math.max(0, GAME_MIN_SECONDS - elapsed);
            await client.query('COMMIT');
            return res.status(409).json({ success: true, sessionId: active.rows[0].session_id, remainingSeconds: remaining, adUrl: MONETAG_SDK_URL });
        }

        const sessionId = newRewardSessionId();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await client.query(
            `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at)
             VALUES ($1, $2, 'game', NOW(), $3)`,
            [sessionId, userId, expiresAt]
        );

        await client.query('COMMIT');
        return res.json({ success: true, sessionId, adUrl: MONETAG_SDK_URL });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión de juego.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/game/claim', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { sessionId } = req.body || {};
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
            return res.status(400).json({ success: false, error: 'Recompensa ya otorgada.' });
        }

        const transId = `GAME_${sessionId}`;
        await client.query('UPDATE reward_sessions SET claimed_at = NOW() WHERE session_id = $1', [sessionId]);
        if (await insertRewardEvent(client, { userId, sourceType: 'ARCADE_GAME', transId, points: GAME_REWARD_POINTS })) {
            await client.query('UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2', [GAME_REWARD_POINTS, userId]);
        }

        const uRes = await client.query('SELECT points_balance FROM web_users WHERE id = $1', [userId]);
        await client.query('COMMIT');

        return res.json({ success: true, newBalance: uRes.rows[0].points_balance });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al reclamar puntos del juego.' });
    } finally {
        client.release();
    }
});

// CPX SURVEYS
app.get('/api/v1/cpx/survey-url', verifyToken, async (req, res) => {
    try {
        const uRes = await db.query('SELECT email, country_code FROM web_users WHERE id = $1', [req.user.userId]);
        if (uRes.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        const user = uRes.rows[0];
        const hash = crypto.createHash('md5').update(`${req.user.userId}-${CPX_HASH_SECRET}`).digest('hex');

        const url = `https://offers.cpx-research.com/index.php?app_id=${CPX_APP_ID}&ext_user_id=${req.user.userId}&secure_hash=${hash}&username=${encodeURIComponent(user.email)}&email=${encodeURIComponent(user.email)}&user_country_code=${user.country_code}`;
        return res.json({ success: true, url });
    } catch (err) {
        return res.status(500).json({ success: false, error: 'Error al generar enlace CPX.' });
    }
});

// SOLICITUD DE RETIRO
app.post('/api/v1/withdraw/request', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { method, payout_method, account_details, amount } = req.body || {};
    const selectedMethod = String(payout_method || method || '').toLowerCase();
    const usdAmount = Number(amount);

    if (!PAYOUT_CONFIG[selectedMethod]) {
        return res.status(400).json({ success: false, error: 'Método de pago no válido.' });
    }

    const cfg = PAYOUT_CONFIG[selectedMethod];
    if (!usdAmount || usdAmount < cfg.minAmount) {
        return res.status(400).json({ success: false, error: `El monto mínimo es de $${cfg.minAmount.toFixed(2)} USD.` });
    }

    if (!account_details || account_details.trim().length === 0) {
        return res.status(400).json({ success: false, error: 'Detalles de cuenta requeridos.' });
    }

    const pointsNeeded = Math.round(usdAmount / POINT_TO_CURRENCY_RATIO);
    const feeUsd = (usdAmount * cfg.fixedFeePercent) + cfg.fixedFeeAmount;
    const netUsd = usdAmount - feeUsd;

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const uRes = await client.query('SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE', [userId]);
        if (uRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }

        const balance = Number(uRes.rows[0].points_balance || 0);
        if (balance < pointsNeeded) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Saldo insuficiente. Necesitas ${pointsNeeded} pts.` });
        }

        await client.query('UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2', [pointsNeeded, userId]);
        await client.query(
            `INSERT INTO web_withdrawals (user_id, amount_usd, fee_usd, net_amount_usd, points_deducted, payout_method, payout_destination, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')`,
            [userId, usdAmount, feeUsd, netUsd, pointsNeeded, selectedMethod, account_details.trim()]
        );

        await client.query('COMMIT');
        return res.json({ success: true, message: 'Solicitud de retiro registrada.' });
    } catch (err) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error procesando solicitud de retiro.' });
    } finally {
        client.release();
    }
});

// SERVIDOR
app.listen(PORT, () => {
    console.log(`Servidor activo en el puerto ${PORT}`);
});
