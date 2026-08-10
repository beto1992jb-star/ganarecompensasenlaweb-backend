require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();

// ============================================================
// CONFIGURACIÓN DE PUERTO Y VARIABLES DE ENTORNO
// ============================================================

const PORT = Number(process.env.PORT) || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

const CPX_APP_ID = process.env.CPX_APP_ID || '35135';

// MONETAG CONFIG
const MONETAG_ZONE_ID = process.env.MONETAG_ZONE_ID || '11538152';
const MONETAG_SDK_URL = process.env.MONETAG_SDK_URL || 'https://omg10.com/4/11538152';
const MONETAG_SECRET = process.env.MONETAG_SECRET || '';

// ============================================================
// VALIDACIÓN DE VARIABLES DE ENTORNO
// ============================================================

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET es obligatorio y debe tener al menos 32 caracteres.');
}

if (!ADMIN_SECRET || ADMIN_SECRET.length < 32) {
    throw new Error('ADMIN_SECRET es obligatorio y debe tener al menos 32 caracteres.');
}

if (!DATABASE_URL) {
    throw new Error('DATABASE_URL es obligatorio.');
}

if (!CPX_HASH_SECRET || CPX_HASH_SECRET.length < 16) {
    throw new Error('CPX_HASH_SECRET es obligatorio y debe tener al menos 16 caracteres.');
}

if (!ALLOWED_ORIGIN) {
    throw new Error('ALLOWED_ORIGIN es obligatorio.');
}

// ============================================================
// CONFIGURACIÓN DE NEGOCIO
// ============================================================

const POINT_TO_CURRENCY_RATIO = 0.001; // 1000 puntos = 1 USD

const GAME_REWARD_POINTS = 1;
const REFERRAL_BONUS = 25;

const MAX_VIDEO_REWARDS_PER_DAY = 5;
const MAX_GAME_REWARDS_PER_DAY = 20;

const VIDEO_COOLDOWN_MS = 10 * 60 * 1000;
const GAME_COOLDOWN_MS = 60 * 1000;

const VIDEO_MIN_SECONDS = 45;
const GAME_MIN_SECONDS = 60;

const REWARD_SESSION_MAX_AGE_MS = 15 * 60 * 1000;

const PAYOUT_CONFIG = {
    binance: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.0 },
    mercadopago: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.15 },
    paypal: { minAmount: 5.00, fixedFeePercent: 0.015, fixedFeeAmount: 0.20 }
};

// ============================================================
// EXPRESS & SERVIDOR DE ARCHIVOS ESTÁTICOS
// ============================================================

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '20kb' }));

// Servir archivos estáticos del Frontend
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// HEADERS DE SEGURIDAD
// ============================================================

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    next();
});

// ============================================================
// CORS (MÚLTIPLES ORIGENES ACCESIBLES)
// ============================================================

const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim()).filter(Boolean);

const corsOptions = {
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Origen no permitido por CORS.'));
    },
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With', 'x-admin-secret'],
    credentials: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// ============================================================
// RATE LIMITER
// ============================================================

const rateLimitStores = new Map();

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
    return req.ip || req.socket?.remoteAddress || 'unknown';
}

function rateLimit({ windowMs, max, keyPrefix, message }) {
    return (req, res, next) => {
        const ip = getClientIp(req);
        const key = `${keyPrefix}:${ip}`;
        const now = Date.now();

        let record = rateLimitStores.get(key);
        if (!record || now >= record.resetAt) {
            record = { count: 0, resetAt: now + windowMs };
        }

        record.count += 1;
        rateLimitStores.set(key, record);

        res.setHeader('X-RateLimit-Limit', String(max));
        res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - record.count)));

        if (record.count > max) {
            res.setHeader('Retry-After', String(Math.ceil((record.resetAt - now) / 1000)));
            return res.status(429).json({
                success: false,
                error: message || 'Demasiadas solicitudes. Intentá nuevamente más tarde.'
            });
        }
        next();
    };
}

setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitStores.entries()) {
        if (now >= record.resetAt) rateLimitStores.delete(key);
    }
}, 10 * 60 * 1000).unref();

const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, keyPrefix: 'auth', message: 'Demasiados intentos. Esperá unos minutos.' });
const rewardRateLimit = rateLimit({ windowMs: 60 * 1000, max: 30, keyPrefix: 'reward' });
const withdrawRateLimit = rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: 'withdraw' });
const cpxRateLimit = rateLimit({ windowMs: 60 * 1000, max: 30, keyPrefix: 'cpx' });

// ============================================================
// POSTGRESQL
// ============================================================

const db = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    application_name: 'ganarecompensasenlaweb-backend'
});

db.on('error', err => {
    console.error('Error inesperado en cliente inactivo de PostgreSQL:', err);
});

// ============================================================
// AUXILIARES
// ============================================================

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
    if (typeof email !== 'string' || email.length < 5 || email.length > 255) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeCountryCode(countryCode) {
    const value = String(countryCode || 'AR').trim().toUpperCase();
    return /^[A-Z]{2}$/.test(value) ? value : null;
}

function normalizeReferralCode(code) {
    return String(code || '').trim().toUpperCase();
}

function normalizePayoutMethod(method) {
    const value = String(method || '').trim().toLowerCase();
    if (value === 'paypal' || value.includes('paypal')) return 'paypal';
    if (value === 'mercadopago' || value.includes('mercado pago') || value.includes('mercadopago')) return 'mercadopago';
    if (value === 'binance' || value.includes('binance')) return 'binance';
    return null;
}

function normalizeMoney(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return null;
    return Math.round(number * 100) / 100;
}

function newRewardSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function isValidUUID(value) {
    return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isValidRewardSessionId(value) {
    return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function safeRollback(client) {
    return client.query('ROLLBACK').catch(() => {});
}

async function lockRewardOperation(client, userId, rewardType) {
    const key = `${String(userId)}:${String(rewardType)}`;
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [key]);
}

async function getDailyUsage(client, userId) {
    const result = await client.query(
        `SELECT video_count, game_count FROM reward_daily_usage WHERE user_id = $1 AND reward_date = CURRENT_DATE`,
        [userId]
    );
    if (result.rows.length === 0) return { video_count: 0, game_count: 0 };
    return result.rows[0];
}

async function insertRewardEvent(client, { userId, sourceType, transId, points }) {
    const result = await client.query(
        `INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded)
         VALUES ($1, $2, $3, $4) ON CONFLICT (trans_id) DO NOTHING RETURNING id`,
        [userId, sourceType, transId, points]
    );
    return result.rows.length > 0;
}

// ============================================================
// TABLAS E INICIALIZACIÓN
// ============================================================

async function ensureRewardTables() {
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

    await db.query(`
        ALTER TABLE reward_sessions ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ NULL;
        ALTER TABLE reward_sessions ADD COLUMN IF NOT EXISTS points_awarded INTEGER DEFAULT 0;
        CREATE INDEX IF NOT EXISTS idx_reward_sessions_user_type ON reward_sessions(user_id, reward_type);
        CREATE INDEX IF NOT EXISTS idx_reward_sessions_claimed ON reward_sessions(user_id, reward_type, claimed_at);
        CREATE INDEX IF NOT EXISTS idx_reward_sessions_expiry ON reward_sessions(expires_at);
    `);

    await db.query(`DELETE FROM reward_sessions WHERE expires_at < NOW() - INTERVAL '2 days'`);
}

// ============================================================
// JWT Y SEGURIDAD
// ============================================================

function createUserToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d', issuer: 'ganarecompensasenlaweb' }
    );
}

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Acceso denegado. Token no provisto.' });
    }
    const token = authHeader.slice(7).trim();
    if (!token) {
        return res.status(401).json({ success: false, error: 'Token no provisto.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'ganarecompensasenlaweb' });
        if (!decoded || !decoded.userId || !isValidUUID(String(decoded.userId))) {
            return res.status(403).json({ success: false, error: 'Token inválido.' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ success: false, error: 'Token inválido o expirado.' });
    }
};

const verifyAdmin = (req, res, next) => {
    const provided = req.headers['x-admin-secret'];
    if (typeof provided !== 'string' || provided.length === 0) {
        return res.status(401).json({ success: false, error: 'No autorizado.' });
    }
    const providedBuffer = Buffer.from(provided);
    const expectedBuffer = Buffer.from(ADMIN_SECRET);

    if (providedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedBuffer, expectedBuffer)) {
        return res.status(401).json({ success: false, error: 'No autorizado.' });
    }
    next();
};

// ============================================================
// HEALTH CHECK & RAÍZ
// ============================================================

app.get('/health', async (req, res) => {
    try {
        await db.query('SELECT 1');
        return res.status(200).json({ success: true, status: 'ok', database: 'connected' });
    } catch (error) {
        return res.status(503).json({ success: false, status: 'error', database: 'unavailable' });
    }
});

app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
    }
    return res.status(200).json({
        success: true,
        message: "API Backend de GanaRecompensasEnLaWeb activa y funcionando 🚀",
        version: "1.0.0"
    });
});

// ============================================================
// CPX - SURVEY URL & POSTBACK
// ============================================================

app.get('/api/v1/cpx/survey-url', verifyToken, cpxRateLimit, async (req, res) => {
    try {
        const result = await db.query(`SELECT id, email, country_code FROM web_users WHERE id = $1`, [req.user.userId]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        const user = result.rows[0];
        const userId = String(user.id);
        const secureHash = crypto.createHash('md5').update(`${userId}-${CPX_HASH_SECRET}`).digest('hex');

        const params = new URLSearchParams({
            app_id: String(CPX_APP_ID),
            ext_user_id: userId,
            secure_hash: secureHash,
            username: user.email,
            email: user.email,
            user_country_code: user.country_code || 'AR'
        });

        return res.json({ success: true, url: `https://offers.cpx-research.com/index.php?${params.toString()}` });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'No se pudo preparar CPX Research.' });
    }
});

app.get('/api/cpx-postback', async (req, res) => {
    const { user_id, amount_usd, trans_id, status, hash } = req.query;
    if (!user_id || !trans_id || status === undefined || status === null || !hash) return res.status(200).send('OK');
    if (!isValidUUID(String(user_id))) return res.status(200).send('OK');

    const transactionId = String(trans_id).trim();
    const computedHash = crypto.createHash('md5').update(`${transactionId}-${CPX_HASH_SECRET}`).digest('hex');
    if (computedHash !== String(hash).trim().toLowerCase()) return res.status(200).send('OK');

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const userCheck = await client.query(`SELECT id FROM web_users WHERE id = $1`, [user_id]);
        if (userCheck.rows.length === 0) {
            await safeRollback(client);
            return res.status(200).send('OK');
        }

        if (String(status) === '1') {
            const amount = Number(amount_usd);
            if (!Number.isFinite(amount) || amount <= 0) {
                await safeRollback(client);
                return res.status(200).send('OK');
            }
            const points = Math.round(amount / POINT_TO_CURRENCY_RATIO);
            const eventInserted = await insertRewardEvent(client, { userId: user_id, sourceType: 'CPX_RESEARCH', transId: transactionId, points });
            if (eventInserted) {
                await client.query(`UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2`, [points, user_id]);
            }
        } else if (String(status) === '2') {
            const original = await client.query(`SELECT user_id, points_awarded FROM web_reward_events WHERE trans_id = $1 AND source_type = 'CPX_RESEARCH' LIMIT 1`, [transactionId]);
            if (original.rows.length > 0 && String(original.rows[0].user_id) === String(user_id)) {
                const points = Math.abs(Number(original.rows[0].points_awarded) || 0);
                if (points > 0) {
                    const reversalInserted = await insertRewardEvent(client, { userId: user_id, sourceType: 'CPX_RESEARCH_REVERSED', transId: `${transactionId}_REV`, points: -points });
                    if (reversalInserted) {
                        await client.query(`UPDATE web_users SET points_balance = GREATEST(0, points_balance - $1) WHERE id = $2`, [points, user_id]);
                    }
                }
            }
        }
        await client.query('COMMIT');
        return res.status(200).send('OK');
    } catch (error) {
        await safeRollback(client);
        return res.status(200).send('OK');
    } finally {
        client.release();
    }
});

// ============================================================
// MONETAG POSTBACK
// ============================================================

app.get('/api/monetag-postback', async (req, res) => {
    const { ymid, subid, secret, payout, sum } = req.query;
    
    if (MONETAG_SECRET && secret !== MONETAG_SECRET) {
        return res.status(403).send('Forbidden');
    }

    const sessionId = ymid || subid;
    if (!sessionId || !isValidRewardSessionId(String(sessionId))) {
        return res.status(200).send('OK');
    }

    const rawUsd = payout || sum || 0;
    const usdAmount = Number(rawUsd);
    const calculatedPoints = Number.isFinite(usdAmount) && usdAmount > 0 
        ? Math.round(usdAmount / POINT_TO_CURRENCY_RATIO) 
        : 10;

    try {
        await db.query(
            `UPDATE reward_sessions 
             SET confirmed_at = NOW(), 
                 points_awarded = $1 
             WHERE session_id = $2 AND reward_type = 'video'`,
            [calculatedPoints, sessionId]
        );
        return res.status(200).send('OK');
    } catch (err) {
        console.error('Error procesando postback Monetag:', err);
        return res.status(200).send('OK');
    }
});

// ============================================================
// AUTH (REGISTER / LOGIN / FORGOT PASSWORD)
// ============================================================

app.post('/api/v1/auth/register', authRateLimit, async (req, res) => {
    const { email, password, referral_code, country_code } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ success: false, error: 'Email y contraseña requeridos.' });
    }

    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail)) return res.status(400).json({ success: false, error: 'El correo no es válido.' });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ success: false, error: 'La contraseña debe tener entre 8 y 128 caracteres.' });

    const userCountry = normalizeCountryCode(country_code);
    if (!userCountry) return res.status(400).json({ success: false, error: 'Código de país inválido.' });

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`register:${normalizedEmail}`]);

        const checkUser = await client.query(`SELECT id FROM web_users WHERE email = $1`, [normalizedEmail]);
        if (checkUser.rows.length > 0) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'El correo electrónico ya está registrado.' });
        }

        let referrerId = null;
        const referralCode = normalizeReferralCode(referral_code);
        if (referralCode) {
            const referrerCheck = await client.query(`SELECT id FROM web_users WHERE referral_code = $1 LIMIT 1`, [referralCode]);
            if (referrerCheck.rows.length > 0) referrerId = referrerCheck.rows[0].id;
        }

        let myReferralCode = null;
        for (let i = 0; i < 10; i++) {
            const candidate = crypto.randomBytes(8).toString('hex').toUpperCase().slice(0, 16);
            const exists = await client.query(`SELECT 1 FROM web_users WHERE referral_code = $1 LIMIT 1`, [candidate]);
            if (exists.rows.length === 0) { myReferralCode = candidate; break; }
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = await client.query(
            `INSERT INTO web_users (email, password_hash, country_code, referral_code, referred_by)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, email, country_code, tier_level, points_balance, referral_code, total_referrals`,
            [normalizedEmail, hashedPassword, userCountry, myReferralCode, referrerId]
        );

        const user = newUser.rows[0];

        if (referrerId) {
            const refTransId = `REF_${user.id}_${crypto.randomBytes(8).toString('hex')}`;
            const eventInserted = await insertRewardEvent(client, { userId: referrerId, sourceType: 'REFERRAL_BONUS', transId: refTransId, points: REFERRAL_BONUS });
            if (eventInserted) {
                await client.query(`UPDATE web_users SET points_balance = points_balance + $1, total_referrals = total_referrals + 1 WHERE id = $2`, [REFERRAL_BONUS, referrerId]);
            }
        }

        await client.query('COMMIT');
        const token = createUserToken(user);
        return res.json({ success: true, user, token });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al registrar el usuario.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/auth/login', authRateLimit, async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ success: false, error: 'Email y contraseña requeridos.' });
    }

    const normalizedEmail = normalizeEmail(email);
    try {
        const userRes = await db.query(
            `SELECT id, email, password_hash, country_code, tier_level, points_balance, referral_code, total_referrals
             FROM web_users WHERE email = $1 LIMIT 1`,
            [normalizedEmail]
        );

        if (userRes.rows.length === 0 || !userRes.rows[0].password_hash) {
            return res.status(401).json({ success: false, error: 'Credenciales incorrectas.' });
        }

        const user = userRes.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Credenciales incorrectas.' });
        }

        delete user.password_hash;
        const token = createUserToken(user);
        return res.json({ success: true, user, token });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Error al iniciar sesión.' });
    }
});

app.post('/api/v1/auth/forgot-password', authRateLimit, async (req, res) => {
    const { email } = req.body || {};
    if (typeof email !== 'string' || !isValidEmail(email)) {
        return res.status(400).json({ success: false, error: 'Correo electrónico no válido.' });
    }
    return res.json({
        success: true,
        message: 'Si el correo electrónico se encuentra registrado, recibirás las instrucciones para restablecer tu contraseña.'
    });
});

app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const userRes = await db.query(
            `SELECT id, email, country_code, tier_level, points_balance, referral_code, total_referrals
             FROM web_users WHERE id = $1 LIMIT 1`,
            [req.user.userId]
        );
        if (userRes.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        return res.json({ success: true, user: userRes.rows[0] });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Error del servidor.' });
    }
});

app.get('/api/v1/user/balance', verifyToken, async (req, res) => {
    try {
        const result = await db.query(`SELECT points_balance FROM web_users WHERE id = $1`, [req.user.userId]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        return res.json({ success: true, balance: result.rows[0].points_balance });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Error del servidor.' });
    }
});

// ============================================================
// MONETAG VIDEO ENDPOINTS
// ============================================================

app.get('/api/v1/web-video/status', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { sessionId } = req.query;

    try {
        let activeSession = null;

        if (sessionId && isValidRewardSessionId(String(sessionId))) {
            const resSession = await db.query(
                `SELECT * FROM reward_sessions WHERE session_id = $1 AND user_id = $2 AND reward_type = 'video'`,
                [sessionId, userId]
            );
            if (resSession.rows.length > 0) activeSession = resSession.rows[0];
        }

        if (!activeSession) {
            const resActive = await db.query(
                `SELECT * FROM reward_sessions WHERE user_id = $1 AND reward_type = 'video' AND claimed_at IS NULL AND expires_at > NOW() ORDER BY started_at DESC LIMIT 1`,
                [userId]
            );
            if (resActive.rows.length > 0) activeSession = resActive.rows[0];
        }

        const recentClaim = await db.query(
            `SELECT claimed_at FROM reward_sessions WHERE user_id = $1 AND reward_type = 'video' AND claimed_at IS NOT NULL ORDER BY claimed_at DESC LIMIT 1`,
            [userId]
        );

        let cooldownSeconds = 0;
        if (recentClaim.rows.length > 0) {
            const elapsed = Date.now() - new Date(recentClaim.rows[0].claimed_at).getTime();
            if (elapsed < VIDEO_COOLDOWN_MS) {
                cooldownSeconds = Math.ceil((VIDEO_COOLDOWN_MS - elapsed) / 1000);
            }
        }

        return res.json({
            success: true,
            exists: !!activeSession,
            claimed: activeSession ? !!activeSession.claimed_at : false,
            confirmed: activeSession ? !!activeSession.confirmed_at : false,
            cooldownSeconds
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: 'Error al consultar estado.' });
    }
});

app.post('/api/v1/web-video/start', verifyToken, rewardRateLimit, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();

    try {
        await client.query('BEGIN');
        await lockRewardOperation(client, userId, 'video');

        const usage = await getDailyUsage(client, userId);
        if (Number(usage.video_count) >= MAX_VIDEO_REWARDS_PER_DAY) {
            await safeRollback(client);
            return res.status(429).json({
                success: false,
                error: `Alcanzaste el máximo de ${MAX_VIDEO_REWARDS_PER_DAY} recompensas de video por día.`
            });
        }

        const recent = await client.query(
            `SELECT claimed_at FROM reward_sessions WHERE user_id = $1 AND reward_type = 'video' AND claimed_at IS NOT NULL ORDER BY claimed_at DESC LIMIT 1`,
            [userId]
        );

        if (recent.rows.length > 0) {
            const elapsed = Date.now() - new Date(recent.rows[0].claimed_at).getTime();
            if (elapsed < VIDEO_COOLDOWN_MS) {
                const remaining = Math.ceil((VIDEO_COOLDOWN_MS - elapsed) / 1000);
                await safeRollback(client);
                return res.status(429).json({ success: false, error: `Esperá ${remaining} segundos para otro anuncio.` });
            }
        }

        const active = await client.query(
            `SELECT session_id FROM reward_sessions WHERE user_id = $1 AND reward_type = 'video' AND claimed_at IS NULL AND expires_at > NOW() LIMIT 1`,
            [userId]
        );

        let sessionId;
        if (active.rows.length > 0) {
            sessionId = active.rows[0].session_id;
        } else {
            sessionId = newRewardSessionId();
            const started = new Date();
            const expires = new Date(started.getTime() + REWARD_SESSION_MAX_AGE_MS);

            await client.query(
                `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at) VALUES ($1, $2, 'video', $3, $4)`,
                [sessionId, userId, started, expires]
            );
        }

        await client.query('COMMIT');

        const directLinkUrl = process.env.MONETAG_DIRECT_LINK_URL || "https://example.com/ad-link";

        return res.json({
            success: true,
            sessionId,
            ymid: sessionId,
            adUrl: directLinkUrl,
            waitSeconds: VIDEO_MIN_SECONDS,
            monetag: {
                zoneId: MONETAG_ZONE_ID,
                sdkUrl: MONETAG_SDK_URL,
                sdkName: `show_${MONETAG_ZONE_ID}`
            }
        });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'No se pudo iniciar la recompensa.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/web-video/claim', verifyToken, rewardRateLimit, async (req, res) => {
    const { sessionId } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) {
        return res.status(400).json({ success: false, error: 'Sesión de recompensa inválida.' });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        await lockRewardOperation(client, userId, 'video');

        const sessionRes = await client.query(
            `SELECT * FROM reward_sessions WHERE session_id = $1 AND user_id = $2 AND reward_type = 'video' FOR UPDATE`,
            [sessionId, userId]
        );

        if (sessionRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Sesión no encontrada.' });
        }

        const session = sessionRes.rows[0];
        if (session.claimed_at) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Esta recompensa ya fue utilizada.' });
        }

        if (MONETAG_SECRET && !session.confirmed_at) {
            await safeRollback(client);
            return res.status(400).json({
                success: false,
                errorCode: 'WAITING_MONETAG_CONFIRMATION',
                error: 'Esperando confirmación del servidor de Monetag...'
            });
        }

        const now = Date.now();
        if (now < new Date(session.started_at).getTime() + VIDEO_MIN_SECONDS * 1000) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Todavía no pasaron ${VIDEO_MIN_SECONDS} segundos.` });
        }

        if (now > new Date(session.expires_at).getTime()) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'La sesión de recompensa expiró.' });
        }

        const realPoints = Number(session.points_awarded) > 0 ? Number(session.points_awarded) : 10;

        const usageUpdate = await client.query(
            `INSERT INTO reward_daily_usage (user_id, reward_date, video_count, game_count)
             VALUES ($1, CURRENT_DATE, 1, 0)
             ON CONFLICT (user_id, reward_date)
             DO UPDATE SET video_count = reward_daily_usage.video_count + 1
             WHERE reward_daily_usage.video_count < $2 RETURNING video_count`,
            [userId, MAX_VIDEO_REWARDS_PER_DAY]
        );

        if (usageUpdate.rows.length === 0) {
            await safeRollback(client);
            return res.status(429).json({ success: false, error: 'Límite diario de videos alcanzado.' });
        }

        const transId = `VIDEO_${sessionId}`;
        const eventInserted = await insertRewardEvent(client, { userId, sourceType: 'WEB_VIDEO', transId, points: realPoints });

        if (!eventInserted) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Esta recompensa ya fue procesada.' });
        }

        await client.query(`UPDATE reward_sessions SET claimed_at = NOW() WHERE session_id = $1`, [sessionId]);
        const balanceRes = await client.query(
            `UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2 RETURNING points_balance`,
            [realPoints, userId]
        );

        await client.query('COMMIT');
        return res.json({
            success: true,
            pointsAwarded: realPoints,
            newBalance: balanceRes.rows[0].points_balance,
            cooldownSeconds: VIDEO_COOLDOWN_MS / 1000
        });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error interno del servidor.' });
    } finally {
        client.release();
    }
});

// ============================================================
// GAME (START & CLAIM)
// ============================================================

app.post('/api/v1/game/start', verifyToken, rewardRateLimit, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.connect();

    try {
        await client.query('BEGIN');
        await lockRewardOperation(client, userId, 'game');

        const usage = await getDailyUsage(client, userId);
        if (Number(usage.game_count) >= MAX_GAME_REWARDS_PER_DAY) {
            await safeRollback(client);
            return res.status(429).json({
                success: false,
                error: `Alcanzaste el máximo de ${MAX_GAME_REWARDS_PER_DAY} recompensas de juego por día.`
            });
        }

        const recent = await client.query(
            `SELECT claimed_at FROM reward_sessions WHERE user_id = $1 AND reward_type = 'game' AND claimed_at IS NOT NULL ORDER BY claimed_at DESC LIMIT 1`,
            [userId]
        );

        if (recent.rows.length > 0) {
            const elapsed = Date.now() - new Date(recent.rows[0].claimed_at).getTime();
            if (elapsed < GAME_COOLDOWN_MS) {
                const remaining = Math.ceil((GAME_COOLDOWN_MS - elapsed) / 1000);
                await safeRollback(client);
                return res.status(429).json({ success: false, error: `Esperá ${remaining} segundos para iniciar otra sesión de juego.` });
            }
        }

        const active = await client.query(
            `SELECT session_id FROM reward_sessions WHERE user_id = $1 AND reward_type = 'game' AND claimed_at IS NULL AND expires_at > NOW() LIMIT 1`,
            [userId]
        );

        let sessionId;
        if (active.rows.length > 0) {
            sessionId = active.rows[0].session_id;
        } else {
            sessionId = newRewardSessionId();
            const started = new Date();
            const expires = new Date(started.getTime() + REWARD_SESSION_MAX_AGE_MS);

            await client.query(
                `INSERT INTO reward_sessions (session_id, user_id, reward_type, started_at, expires_at) VALUES ($1, $2, 'game', $3, $4)`,
                [sessionId, userId, started, expires]
            );
        }

        await client.query('COMMIT');

        return res.json({
            success: true,
            sessionId,
            waitSeconds: GAME_MIN_SECONDS
        });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'No se pudo iniciar la sesión de juego.' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/game/claim', verifyToken, rewardRateLimit, async (req, res) => {
    const { sessionId } = req.body || {};
    const userId = req.user.userId;

    if (!isValidRewardSessionId(sessionId)) {
        return res.status(400).json({ success: false, error: 'Sesión de recompensa inválida.' });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        await lockRewardOperation(client, userId, 'game');

        const sessionRes = await client.query(
            `SELECT * FROM reward_sessions WHERE session_id = $1 AND user_id = $2 AND reward_type = 'game' FOR UPDATE`,
            [sessionId, userId]
        );

        if (sessionRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Sesión no encontrada.' });
        }

        const session = sessionRes.rows[0];
        if (session.claimed_at) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Esta recompensa ya fue reclamada.' });
        }

        const now = Date.now();
        if (now < new Date(session.started_at).getTime() + GAME_MIN_SECONDS * 1000) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: `Todavía no pasaron ${GAME_MIN_SECONDS} segundos de juego.` });
        }

        if (now > new Date(session.expires_at).getTime()) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'La sesión de recompensa expiró.' });
        }

        const usageUpdate = await client.query(
            `INSERT INTO reward_daily_usage (user_id, reward_date, video_count, game_count)
             VALUES ($1, CURRENT_DATE, 0, 1)
             ON CONFLICT (user_id, reward_date)
             DO UPDATE SET game_count = reward_daily_usage.game_count + 1
             WHERE reward_daily_usage.game_count < $2 RETURNING game_count`,
            [userId, MAX_GAME_REWARDS_PER_DAY]
        );

        if (usageUpdate.rows.length === 0) {
            await safeRollback(client);
            return res.status(429).json({ success: false, error: 'Límite diario de juego alcanzado.' });
        }

        const transId = `GAME_${sessionId}`;
        const eventInserted = await insertRewardEvent(client, { userId, sourceType: 'WEB_GAME', transId, points: GAME_REWARD_POINTS });

        if (!eventInserted) {
            await safeRollback(client);
            return res.status(409).json({ success: false, error: 'Esta recompensa ya fue procesada.' });
        }

        await client.query(`UPDATE reward_sessions SET claimed_at = NOW() WHERE session_id = $1`, [sessionId]);
        const balanceRes = await client.query(
            `UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2 RETURNING points_balance`,
            [GAME_REWARD_POINTS, userId]
        );

        await client.query('COMMIT');
        return res.json({
            success: true,
            pointsAwarded: GAME_REWARD_POINTS,
            newBalance: balanceRes.rows[0].points_balance,
            cooldownSeconds: GAME_COOLDOWN_MS / 1000
        });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error interno del servidor.' });
    } finally {
        client.release();
    }
});

// ============================================================
// RETIRAR (WITHDRAWALS)
// ============================================================

const processWithdrawal = async (req, res) => {
    const { amount, method, destination, details, payout_method, account_details } = req.body || {};
    const userId = req.user.userId;

    const payoutDestination = destination || details || account_details;
    const selectedMethod = method || payout_method;
    const parsedAmount = normalizeMoney(amount);
    const normalizedMethod = normalizePayoutMethod(selectedMethod);

    if (!parsedAmount || parsedAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Monto inválido.' });
    }

    if (!normalizedMethod || !PAYOUT_CONFIG[normalizedMethod]) {
        return res.status(400).json({ success: false, error: 'Método de pago no soportado.' });
    }

    if (typeof payoutDestination !== 'string' || payoutDestination.trim().length === 0 || payoutDestination.length > 255) {
        return res.status(400).json({ success: false, error: 'Destino de retiro inválido.' });
    }

    const config = PAYOUT_CONFIG[normalizedMethod];
    if (parsedAmount < config.minAmount) {
        return res.status(400).json({
            success: false,
            error: `El monto mínimo para ${normalizedMethod} es de $${config.minAmount.toFixed(2)} USD.`
        });
    }

    const fee = normalizeMoney((parsedAmount * config.fixedFeePercent) + config.fixedFeeAmount);
    const netAmount = normalizeMoney(parsedAmount - fee);
    const requiredPoints = Math.round(parsedAmount / POINT_TO_CURRENCY_RATIO);

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`withdraw:${userId}`]);

        const userRes = await client.query(`SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE`, [userId]);
        if (userRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }

        const currentBalance = Number(userRes.rows[0].points_balance);
        if (currentBalance < requiredPoints) {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'Saldo de puntos insuficiente.' });
        }

        await client.query(`UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2`, [requiredPoints, userId]);

        const withdrawRes = await client.query(
            `INSERT INTO web_withdrawals (user_id, amount_usd, fee_usd, net_amount_usd, points_deducted, payout_method, payout_destination, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
             RETURNING id, status, created_at`,
            [userId, parsedAmount, fee, netAmount, requiredPoints, normalizedMethod, payoutDestination.trim()]
        );

        await client.query('COMMIT');

        return res.json({
            success: true,
            withdrawal: withdrawRes.rows[0],
            deductedPoints: requiredPoints,
            netAmountUsd: netAmount,
            message: 'Solicitud de retiro registrada exitosamente.'
        });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al procesar la solicitud de retiro.' });
    } finally {
        client.release();
    }
};

app.post('/api/v1/user/withdraw', verifyToken, withdrawRateLimit, processWithdrawal);
app.post('/api/v1/withdraw/request', verifyToken, withdrawRateLimit, processWithdrawal);
app.post('/api/v1/withdraw', verifyToken, withdrawRateLimit, processWithdrawal);

// ============================================================
// ADMIN ENDPOINTS
// ============================================================

app.get('/api/v1/admin/withdrawals', verifyAdmin, async (req, res) => {
    try {
        const result = await db.query(
            `SELECT w.*, u.email FROM web_withdrawals w JOIN web_users u ON w.user_id = u.id ORDER BY w.created_at DESC LIMIT 100`
        );
        return res.json({ success: true, withdrawals: result.rows });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Error al obtener los retiros.' });
    }
});

app.patch('/api/v1/admin/withdrawals/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body || {};

    if (!['approved', 'rejected', 'completed'].includes(status)) {
        return res.status(400).json({ success: false, error: 'Estado no válido.' });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');

        const currentRes = await client.query(`SELECT * FROM web_withdrawals WHERE id = $1 FOR UPDATE`, [id]);
        if (currentRes.rows.length === 0) {
            await safeRollback(client);
            return res.status(404).json({ success: false, error: 'Retiro no encontrado.' });
        }

        const withdrawal = currentRes.rows[0];

        if (withdrawal.status === 'rejected' || withdrawal.status === 'completed') {
            await safeRollback(client);
            return res.status(400).json({ success: false, error: 'El retiro ya fue finalizado previamente.' });
        }

        if (status === 'rejected') {
            await client.query(
                `UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2`,
                [withdrawal.points_deducted, withdrawal.user_id]
            );
        }

        const updated = await client.query(
            `UPDATE web_withdrawals SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *`,
            [status, id]
        );

        await client.query('COMMIT');
        return res.json({ success: true, withdrawal: updated.rows[0] });
    } catch (error) {
        await safeRollback(client);
        return res.status(500).json({ success: false, error: 'Error al actualizar el retiro.' });
    } finally {
        client.release();
    }
});

// ============================================================
// MAPEO DE COMPATIBILIDAD Y REDIRECCIONES DE RUTAS API
// ============================================================

const forwardRequest = (targetUrl) => (req, res, next) => {
    req.url = targetUrl;
    app.handle(req, res, next);
};

app.use('/api/v1/ad/start', forwardRequest('/api/v1/web-video/start'));
app.use('/api/v1/ad/claim', forwardRequest('/api/v1/web-video/claim'));
app.use('/api/ads/watch', forwardRequest('/api/v1/web-video/start'));
app.use('/api/ads/claim', forwardRequest('/api/v1/web-video/claim'));
app.use('/api/game/start', forwardRequest('/api/v1/game/start'));
app.use('/api/game/claim', forwardRequest('/api/v1/game/claim'));

// Manejo genérico de rutas no encontradas en API
app.use('/api/*', (req, res) => {
    res.status(404).json({ success: false, error: 'Ruta de API no encontrada.' });
});

// Capture-all para manejar SPA / navegación directa a páginas HTML
app.get('*', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
    }
    res.status(404).json({ success: false, error: 'Página no encontrada.' });
});

// ============================================================
// INICIALIZACIÓN DEL SERVIDOR
// ============================================================

async function startServer() {
    try {
        await ensureRewardTables();
        app.listen(PORT, () => {
            console.log(`Servidor iniciado y escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('Error al inicializar las tablas de la base de datos:', error);
        process.exit(1);
    }
}

startServer();
