```javascript
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ============================================================
// CONFIGURACIÓN
// ============================================================

const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

// Producción: estas variables deben existir.
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
        'JWT_SECRET es obligatorio y debe tener al menos 32 caracteres.'
    );
}

if (!DATABASE_URL) {
    throw new Error('DATABASE_URL es obligatorio.');
}

if (!CPX_HASH_SECRET || CPX_HASH_SECRET.length < 16) {
    throw new Error(
        'CPX_HASH_SECRET es obligatorio y debe tener al menos 16 caracteres.'
    );
}

if (!ALLOWED_ORIGIN) {
    throw new Error(
        'ALLOWED_ORIGIN es obligatorio. Configúralo en Render con el dominio de Netlify.'
    );
}

// ============================================================
// CONFIGURACIÓN DE NEGOCIO
// ============================================================

const POINT_TO_CURRENCY_RATIO = 0.001;

// 1000 puntos = $1 USD
const VIDEO_REWARD_POINTS = 5;
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
    binance: {
        minAmount: 5.00,
        fixedFeePercent: 0.0,
        fixedFeeAmount: 0.0
    },
    mercadopago: {
        minAmount: 5.00,
        fixedFeePercent: 0.0,
        fixedFeeAmount: 0.15
    },
    paypal: {
        minAmount: 5.00,
        fixedFeePercent: 0.015,
        fixedFeeAmount: 0.20
    }
};

// ============================================================
// EXPRESS / SEGURIDAD
// ============================================================

app.disable('x-powered-by');
app.set('trust proxy', 1);

// Limitar tamaño de requests JSON.
app.use(express.json({ limit: '20kb' }));

// Headers básicos de seguridad.
// No reemplazan Helmet, pero permiten mejorar seguridad sin agregar
// una dependencia adicional al package.json en esta etapa.
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

    next();
});

// ============================================================
// CORS
// ============================================================

const allowedOrigins = ALLOWED_ORIGIN
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

const corsOptions = {
    origin: function (origin, callback) {
        // Permitir requests sin Origin, por ejemplo health checks.
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error('Origen no permitido por CORS.'));
    },
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'x-admin-secret'
    ],
    credentials: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// ============================================================
// RATE LIMITER SIMPLE EN MEMORIA
// ============================================================
//
// No reemplaza un rate limiter distribuido si algún día usás varias
// instancias. Para una instancia de Render sirve como primera barrera.
// ============================================================

const rateLimitStores = new Map();

function rateLimit({
    windowMs,
    max,
    keyPrefix,
    message = 'Demasiadas solicitudes. Intentá nuevamente más tarde.'
}) {
    return (req, res, next) => {
        const ip =
            req.ip ||
            req.headers['x-forwarded-for'] ||
            req.socket.remoteAddress ||
            'unknown';

        const key = `${keyPrefix}:${String(ip).split(',')[0].trim()}`;
        const now = Date.now();

        let record = rateLimitStores.get(key);

        if (!record || now >= record.resetAt) {
            record = {
                count: 0,
                resetAt: now + windowMs
            };
        }

        record.count += 1;
        rateLimitStores.set(key, record);

        res.setHeader(
            'X-RateLimit-Limit',
            String(max)
        );

        res.setHeader(
            'X-RateLimit-Remaining',
            String(Math.max(0, max - record.count))
        );

        if (record.count > max) {
            res.setHeader(
                'Retry-After',
                String(Math.ceil((record.resetAt - now) / 1000))
            );

            return res.status(429).json({
                success: false,
                error: message
            });
        }

        next();
    };
}

// Limpieza periódica del rate limiter.
setInterval(() => {
    const now = Date.now();

    for (const [key, record] of rateLimitStores.entries()) {
        if (now >= record.resetAt) {
            rateLimitStores.delete(key);
        }
    }
}, 10 * 60 * 1000).unref();

// Límites generales.
const authRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    keyPrefix: 'auth',
    message: 'Demasiados intentos. Esperá unos minutos antes de volver a intentar.'
});

const rewardRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyPrefix: 'reward'
});

const withdrawRateLimit = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    keyPrefix: 'withdraw'
});

// ============================================================
// POSTGRESQL
// ============================================================

const db = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

db.on('error', (err) => {
    console.error(
        'Error inesperado en cliente inactivo de PostgreSQL:',
        err
    );
});

// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    if (email.length < 5 || email.length > 255) return false;

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeCountryCode(countryCode) {
    const value = String(countryCode || 'AR')
        .trim()
        .toUpperCase();

    return /^[A-Z]{2}$/.test(value) ? value : null;
}

function normalizeReferralCode(code) {
    return String(code || '')
        .trim()
        .toUpperCase();
}

function normalizePayoutMethod(method) {
    const value = String(method || '')
        .trim()
        .toLowerCase();

    if (value === 'paypal' || value.includes('paypal')) {
        return 'paypal';
    }

    if (
        value === 'mercadopago' ||
        value === 'mercado pago' ||
        value.includes('mercadopago')
    ) {
        return 'mercadopago';
    }

    if (value === 'binance' || value.includes('binance')) {
        return 'binance';
    }

    return null;
}

function normalizeMoney(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return null;
    }

    return Math.round(number * 100) / 100;
}

function newRewardSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// Lock lógico de PostgreSQL por usuario + tipo de recompensa.
// Evita que dos requests simultáneos puedan saltarse cooldown/límites.
async function lockRewardOperation(client, userId, rewardType) {
    const key = `${String(userId)}:${String(rewardType)}`;

    await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [key]
    );
}

async function getDailyUsage(client, userId) {
    const result = await client.query(
        `SELECT video_count, game_count
         FROM reward_daily_usage
         WHERE user_id = $1
           AND reward_date = CURRENT_DATE`,
        [String(userId)]
    );

    return result.rows[0] || {
        video_count: 0,
        game_count: 0
    };
}

// ============================================================
// CREACIÓN DE TABLAS DE RECOMPENSAS
// ============================================================

async function ensureRewardTables() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS reward_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            reward_type TEXT NOT NULL
                CHECK (reward_type IN ('video', 'game')),
            started_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            claimed_at TIMESTAMPTZ NULL
        );

        CREATE INDEX IF NOT EXISTS idx_reward_sessions_user_type
        ON reward_sessions(user_id, reward_type);

        CREATE INDEX IF NOT EXISTS idx_reward_sessions_claimed
        ON reward_sessions(user_id, reward_type, claimed_at);

        CREATE TABLE IF NOT EXISTS reward_daily_usage (
            user_id TEXT NOT NULL,
            reward_date DATE NOT NULL,
            video_count INTEGER NOT NULL DEFAULT 0,
            game_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, reward_date)
        );
    `);
}

// ============================================================
// MIDDLEWARE JWT
// ============================================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (
        !authHeader ||
        typeof authHeader !== 'string' ||
        !authHeader.startsWith('Bearer ')
    ) {
        return res.status(401).json({
            success: false,
            error: 'Acceso denegado. Token no provisto.'
        });
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Token no provisto.'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded || !decoded.userId) {
            return res.status(403).json({
                success: false,
                error: 'Token inválido.'
            });
        }

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({
            success: false,
            error: 'Token inválido o expirado.'
        });
    }
};

// ============================================================
// MIDDLEWARE ADMIN
// ============================================================

const verifyAdmin = (req, res, next) => {
    const secret = req.headers['x-admin-secret'];

    if (
        !ADMIN_SECRET ||
        typeof secret !== 'string' ||
        secret.length === 0 ||
        secret !== ADMIN_SECRET
    ) {
        return res.status(401).json({
            success: false,
            error: 'No autorizado.'
        });
    }

    next();
};

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Servidor activo',
        status: 'ok'
    });
});

// ============================================================
// CPX - GENERAR URL
// ============================================================

app.get(
    '/api/v1/cpx/survey-url',
    verifyToken,
    async (req, res) => {
        try {
            const result = await db.query(
                `SELECT id, email, country_code
                 FROM web_users
                 WHERE id = $1`,
                [req.user.userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Usuario no encontrado.'
                });
            }

            const user = result.rows[0];
            const userId = String(user.id);

            const secureHash = crypto
                .createHash('md5')
                .update(`${userId}-${CPX_HASH_SECRET}`)
                .digest('hex');

            const params = new URLSearchParams({
                app_id: '35135',
                ext_user_id: userId,
                secure_hash: secureHash,
                username: user.email,
                email: user.email,
                user_country_code: user.country_code || 'AR'
            });

            return res.json({
                success: true,
                url: `https://offers.cpx-research.com/index.php?${params.toString()}`
            });
        } catch (error) {
            console.error(
                'Error generando URL de CPX:',
                error
            );

            return res.status(500).json({
                success: false,
                error: 'No se pudo preparar CPX Research.'
            });
        }
    }
);

// ============================================================
// CPX POSTBACK
// ============================================================

app.get('/api/cpx-postback', async (req, res) => {
    const {
        user_id,
        amount_usd,
        trans_id,
        status,
        hash
    } = req.query;

    if (
        !user_id ||
        !trans_id ||
        status === undefined ||
        status === null ||
        !hash
    ) {
        return res.status(200).send('OK');
    }

    const computedHash = crypto
        .createHash('md5')
        .update(`${trans_id}-${CPX_HASH_SECRET}`)
        .digest('hex');

    if (
        computedHash.toLowerCase() !==
        String(hash).toLowerCase()
    ) {
        console.error('Firma HASH de CPX inválida.');
        return res.status(200).send('OK');
    }

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const userCheck = await client.query(
            'SELECT id FROM web_users WHERE id = $1',
            [user_id]
        );

        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(200).send('OK');
        }

        const transactionId = String(trans_id);

        // ----------------------------------------------------
        // STATUS 1 = COMPLETADA
        // ----------------------------------------------------

        if (String(status) === '1') {
            const amountUsdNumber = Number(amount_usd);

            if (
                !Number.isFinite(amountUsdNumber) ||
                amountUsdNumber <= 0
            ) {
                await client.query('ROLLBACK');
                return res.status(200).send('OK');
            }

            const pointsAwarded = Math.round(
                amountUsdNumber / POINT_TO_CURRENCY_RATIO
            );

            if (pointsAwarded <= 0) {
                await client.query('ROLLBACK');
                return res.status(200).send('OK');
            }

            const existingTx = await client.query(
                `SELECT id
                 FROM web_reward_events
                 WHERE trans_id = $1`,
                [transactionId]
            );

            if (existingTx.rows.length === 0) {
                await client.query(
                    `UPDATE web_users
                     SET points_balance =
                         points_balance + $1
                     WHERE id = $2`,
                    [pointsAwarded, user_id]
                );

                await client.query(
                    `INSERT INTO web_reward_events
                        (user_id, source_type, trans_id, points_awarded)
                     VALUES
                        ($1, $2, $3, $4)
                     ON CONFLICT (trans_id) DO NOTHING`,
                    [
                        user_id,
                        'CPX_RESEARCH',
                        transactionId,
                        pointsAwarded
                    ]
                );
            }
        }

        // ----------------------------------------------------
        // STATUS 2 = REVERSIÓN
        // ----------------------------------------------------

        else if (String(status) === '2') {
            const originalTx = await client.query(
                `SELECT user_id, points_awarded
                 FROM web_reward_events
                 WHERE trans_id = $1
                 LIMIT 1`,
                [transactionId]
            );

            if (originalTx.rows.length > 0) {
                const original = originalTx.rows[0];

                // La reversión solo puede aplicarse al mismo usuario.
                if (String(original.user_id) === String(user_id)) {
                    const reversalId = `${transactionId}_REV`;

                    const existingReversal = await client.query(
                        `SELECT id
                         FROM web_reward_events
                         WHERE trans_id = $1`,
                        [reversalId]
                    );

                    // IMPORTANTE:
                    // Solo descontamos una vez.
                    if (existingReversal.rows.length === 0) {
                        const originalPoints = Math.abs(
                            Number(original.points_awarded) || 0
                        );

                        if (originalPoints > 0) {
                            await client.query(
                                `UPDATE web_users
                                 SET points_balance =
                                     GREATEST(
                                         0,
                                         points_balance - $1
                                     )
                                 WHERE id = $2`,
                                [originalPoints, user_id]
                            );

                            await client.query(
                                `INSERT INTO web_reward_events
                                    (
                                        user_id,
                                        source_type,
                                        trans_id,
                                        points_awarded
                                    )
                                 VALUES
                                    ($1, $2, $3, $4)
                                 ON CONFLICT (trans_id) DO NOTHING`,
                                [
                                    user_id,
                                    'CPX_RESEARCH_REVERSED',
                                    reversalId,
                                    -originalPoints
                                ]
                            );
                        }
                    }
                }
            }
        }

        await client.query('COMMIT');

        return res.status(200).send('OK');
    } catch (error) {
        await client.query('ROLLBACK');

        console.error(
            'Error procesando postback CPX:',
            error
        );

        // CPX normalmente espera respuesta OK para evitar
        // reintentos innecesarios del mismo postback.
        return res.status(200).send('OK');
    } finally {
        client.release();
    }
});

// ============================================================
// AUTH - REGISTRO
// ============================================================

app.post(
    '/api/v1/auth/register',
    authRateLimit,
    async (req, res) => {
        const {
            email,
            password,
            referral_code,
            country_code
        } = req.body || {};

        if (
            typeof email !== 'string' ||
            typeof password !== 'string'
        ) {
            return res.status(400).json({
                success: false,
                error: 'Email y contraseña requeridos.'
            });
        }

        const normalizedEmail = normalizeEmail(email);

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                error: 'El correo electrónico no es válido.'
            });
        }

        if (password.length < 8 || password.length > 128) {
            return res.status(400).json({
                success: false,
                error: 'La contraseña debe tener entre 8 y 128 caracteres.'
            });
        }

        const userCountry = normalizeCountryCode(country_code);

        if (!userCountry) {
            return res.status(400).json({
                success: false,
                error: 'Código de país inválido.'
            });
        }

        const referralCode = normalizeReferralCode(
            referral_code
        );

        if (
            referralCode &&
            !/^[A-Z0-9_-]{3,20}$/.test(referralCode)
        ) {
            return res.status(400).json({
                success: false,
                error: 'Código de referido inválido.'
            });
        }

        const client = await db.connect();

        try {
            await client.query('BEGIN');

            const checkUser = await client.query(
                `SELECT id
                 FROM web_users
                 WHERE email = $1`,
                [normalizedEmail]
            );

            if (checkUser.rows.length > 0) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error: 'El correo electrónico ya está registrado.'
                });
            }

            let referrerId = null;

            if (referralCode) {
                const referrerCheck = await client.query(
                    `SELECT id
                     FROM web_users
                     WHERE referral_code = $1
                     LIMIT 1`,
                    [referralCode]
                );

                if (referrerCheck.rows.length > 0) {
                    referrerId = referrerCheck.rows[0].id;
                }
            }

            const myReferralCode = crypto
                .randomBytes(8)
                .toString('hex')
                .toUpperCase()
                .slice(0, 16);

            const hashedPassword = await bcrypt.hash(
                password,
                12
            );

            const newUser = await client.query(
                `INSERT INTO web_users
                    (
                        email,
                        password_hash,
                        country_code,
                        referral_code,
                        referred_by
                    )
                 VALUES
                    ($1, $2, $3, $4, $5)
                 RETURNING
                    id,
                    email,
                    country_code,
                    tier_level,
                    points_balance,
                    referral_code,
                    total_referrals`,
                [
                    normalizedEmail,
                    hashedPassword,
                    userCountry,
                    myReferralCode,
                    referrerId
                ]
            );

            if (referrerId) {
                await client.query(
                    `UPDATE web_users
                     SET
                        points_balance =
                            points_balance + $1,
                        total_referrals =
                            total_referrals + 1
                     WHERE id = $2`,
                    [
                        REFERRAL_BONUS,
                        referrerId
                    ]
                );

                const referralTransactionId =
                    `REF_${Date.now()}_${crypto
                        .randomBytes(8)
                        .toString('hex')}`;

                await client.query(
                    `INSERT INTO web_reward_events
                        (
                            user_id,
                            source_type,
                            trans_id,
                            points_awarded
                        )
                     VALUES
                        ($1, $2, $3, $4)`,
                    [
                        referrerId,
                        'REFERRAL_BONUS',
                        referralTransactionId,
                        REFERRAL_BONUS
                    ]
                );
            }

            await client.query('COMMIT');

            const userPayload = newUser.rows[0];

            const token = jwt.sign(
                {
                    userId: userPayload.id,
                    email: userPayload.email
                },
                JWT_SECRET,
                {
                    expiresIn: '7d',
                    issuer: 'ganarecompensasenlaweb'
                }
            );

            return res.json({
                success: true,
                user: userPayload,
                token
            });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Error en registro:',
                err
            );

            return res.status(500).json({
                success: false,
                error: 'Error al registrar el usuario.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// AUTH - LOGIN
// ============================================================

app.post(
    '/api/v1/auth/login',
    authRateLimit,
    async (req, res) => {
        const {
            email,
            password
        } = req.body || {};

        if (
            typeof email !== 'string' ||
            typeof password !== 'string'
        ) {
            return res.status(400).json({
                success: false,
                error: 'Email y contraseña requeridos.'
            });
        }

        const normalizedEmail = normalizeEmail(email);

        if (!isValidEmail(normalizedEmail)) {
            return res.status(401).json({
                success: false,
                error: 'Credenciales incorrectas.'
            });
        }

        if (
            password.length === 0 ||
            password.length > 128
        ) {
            return res.status(401).json({
                success: false,
                error: 'Credenciales incorrectas.'
            });
        }

        try {
            const userRes = await db.query(
                `SELECT
                    id,
                    email,
                    password_hash,
                    binance_id,
                    country_code,
                    tier_level,
                    points_balance,
                    daily_videos_watched,
                    referral_code,
                    total_referrals
                 FROM web_users
                 WHERE email = $1
                 LIMIT 1`,
                [normalizedEmail]
            );

            if (
                userRes.rows.length === 0 ||
                !userRes.rows[0].password_hash
            ) {
                return res.status(401).json({
                    success: false,
                    error: 'Credenciales incorrectas.'
                });
            }

            const user = userRes.rows[0];

            const validPassword =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!validPassword) {
                return res.status(401).json({
                    success: false,
                    error: 'Credenciales incorrectas.'
                });
            }

            delete user.password_hash;

            const token = jwt.sign(
                {
                    userId: user.id,
                    email: user.email
                },
                JWT_SECRET,
                {
                    expiresIn: '7d',
                    issuer: 'ganarecompensasenlaweb'
                }
            );

            return res.json({
                success: true,
                user,
                token
            });
        } catch (err) {
            console.error(
                'Error en login:',
                err
            );

            return res.status(500).json({
                success: false,
                error: 'Error al iniciar sesión.'
            });
        }
    }
);

// ============================================================
// BALANCE
// ============================================================

app.get(
    '/api/v1/user/balance',
    verifyToken,
    async (req, res) => {
        try {
            const result = await db.query(
                `SELECT points_balance
                 FROM web_users
                 WHERE id = $1`,
                [req.user.userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Usuario no encontrado.'
                });
            }

            return res.json({
                success: true,
                balance: result.rows[0].points_balance
            });
        } catch (err) {
            console.error(
                'Error obteniendo saldo:',
                err
            );

            return res.status(500).json({
                success: false,
                error: 'Error del servidor.'
            });
        }
    }
);

// ============================================================
// VIDEO - START
// ============================================================

app.post(
    '/api/v1/web-video/start',
    verifyToken,
    rewardRateLimit,
    async (req, res) => {
        const userId = req.user.userId;

        const client = await db.connect();

        try {
            await client.query('BEGIN');

            await lockRewardOperation(
                client,
                userId,
                'video'
            );

            const usage =
                await getDailyUsage(
                    client,
                    userId
                );

            if (
                Number(usage.video_count) >=
                MAX_VIDEO_REWARDS_PER_DAY
            ) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        `Alcanzaste el máximo de ` +
                        `${MAX_VIDEO_REWARDS_PER_DAY} ` +
                        `recompensas de video por día.`
                });
            }

            const recent = await client.query(
                `SELECT claimed_at
                 FROM reward_sessions
                 WHERE user_id = $1
                   AND reward_type = 'video'
                   AND claimed_at IS NOT NULL
                 ORDER BY claimed_at DESC
                 LIMIT 1`,
                [String(userId)]
            );

            if (recent.rows.length > 0) {
                const elapsed =
                    Date.now() -
                    new Date(
                        recent.rows[0].claimed_at
                    ).getTime();

                if (
                    elapsed <
                    VIDEO_COOLDOWN_MS
                ) {
                    const remaining =
                        Math.ceil(
                            (
                                VIDEO_COOLDOWN_MS -
                                elapsed
                            ) / 1000
                        );

                    await client.query('ROLLBACK');

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos ` +
                            `para otro anuncio.`
                    });
                }
            }

            const active = await client.query(
                `SELECT session_id
                 FROM reward_sessions
                 WHERE user_id = $1
                   AND reward_type = 'video'
                   AND claimed_at IS NULL
                   AND expires_at > NOW()
                 LIMIT 1`,
                [String(userId)]
            );

            if (active.rows.length > 0) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    error:
                        'Ya tenés una sesión de video en curso.'
                });
            }

            const sessionId =
                newRewardSessionId();

            const started = new Date();

            const expires =
                new Date(
                    started.getTime() +
                    REWARD_SESSION_MAX_AGE_MS
                );

            await client.query(
                `INSERT INTO reward_sessions
                    (
                        session_id,
                        user_id,
                        reward_type,
                        started_at,
                        expires_at
                    )
                 VALUES
                    ($1, $2, 'video', $3, $4)`,
                [
                    sessionId,
                    String(userId),
                    started,
                    expires
                ]
            );

            await client.query('COMMIT');

            return res.json({
                success: true,
                sessionId,
                waitSeconds: VIDEO_MIN_SECONDS,

                // Este enlace se mantiene porque es el que
                // actualmente utiliza tu frontend.
                // La validación real de visualización debe
                // implementarse mediante postback del proveedor.
                adUrl: 'https://omg10.com/4/11528482'
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error iniciando recompensa de video:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'No se pudo iniciar la recompensa.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// VIDEO - CLAIM
// ============================================================

app.post(
    '/api/v1/web-video/claim',
    verifyToken,
    rewardRateLimit,
    async (req, res) => {
        const {
            sessionId
        } = req.body || {};

        const userId = req.user.userId;

        if (
            typeof sessionId !== 'string' ||
            !/^[a-f0-9]{64}$/.test(sessionId)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Sesión de recompensa inválida.'
            });
        }

        const client = await db.connect();

        try {
            await client.query('BEGIN');

            await lockRewardOperation(
                client,
                userId,
                'video'
            );

            const sessionRes = await client.query(
                `SELECT *
                 FROM reward_sessions
                 WHERE session_id = $1
                   AND user_id = $2
                   AND reward_type = 'video'
                 FOR UPDATE`,
                [
                    sessionId,
                    String(userId)
                ]
            );

            if (sessionRes.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Sesión de recompensa no encontrada.'
                });
            }

            const session =
                sessionRes.rows[0];

            if (session.claimed_at) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    error:
                        'Esta recompensa ya fue utilizada.'
                });
            }

            const startedMs =
                new Date(
                    session.started_at
                ).getTime();

            const expiresMs =
                new Date(
                    session.expires_at
                ).getTime();

            const now = Date.now();

            if (
                now <
                startedMs +
                VIDEO_MIN_SECONDS * 1000
            ) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        `Todavía no pasaron ` +
                        `${VIDEO_MIN_SECONDS} segundos.`
                });
            }

            if (now > expiresMs) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        'La sesión de recompensa expiró. Iniciá otra.'
                });
            }

            const usage =
                await getDailyUsage(
                    client,
                    userId
                );

            if (
                Number(usage.video_count) >=
                MAX_VIDEO_REWARDS_PER_DAY
            ) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de videos alcanzado.'
                });
            }

            const recentClaim =
                await client.query(
                    `SELECT claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'video'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [String(userId)]
                );

            if (recentClaim.rows.length > 0) {
                const elapsed =
                    now -
                    new Date(
                        recentClaim.rows[0].claimed_at
                    ).getTime();

                if (
                    elapsed <
                    VIDEO_COOLDOWN_MS
                ) {
                    await client.query('ROLLBACK');

                    const remaining =
                        Math.ceil(
                            (
                                VIDEO_COOLDOWN_MS -
                                elapsed
                            ) / 1000
                        );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos ` +
                            `para otra recompensa de video.`
                    });
                }
            }

            // Incremento atómico y condicionado.
            const usageUpdate =
                await client.query(
                    `INSERT INTO reward_daily_usage
                        (
                            user_id,
                            reward_date,
                            video_count,
                            game_count
                        )
                     VALUES
                        ($1, CURRENT_DATE, 1, 0)
                     ON CONFLICT (user_id, reward_date)
                     DO UPDATE SET
                        video_count =
                            reward_daily_usage.video_count + 1
                     WHERE
                        reward_daily_usage.video_count <
                        $2
                     RETURNING video_count`,
                    [
                        String(userId),
                        MAX_VIDEO_REWARDS_PER_DAY
                    ]
                );

            if (usageUpdate.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de videos alcanzado.'
                });
            }

            await client.query(
                `UPDATE reward_sessions
                 SET claimed_at = NOW()
                 WHERE session_id = $1`,
                [sessionId]
            );

            const balanceRes =
                await client.query(
                    `UPDATE web_users
                     SET points_balance =
                         points_balance + $1
                     WHERE id = $2
                     RETURNING points_balance`,
                    [
                        VIDEO_REWARD_POINTS,
                        userId
                    ]
                );

            if (balanceRes.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            await client.query('COMMIT');

            return res.json({
                success: true,
                pointsAwarded:
                    VIDEO_REWARD_POINTS,
                newBalance:
                    balanceRes.rows[0].points_balance
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error reclamando recompensa de video:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error interno del servidor.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// GAME - START
// ============================================================

app.post(
    '/api/v1/game/start',
    verifyToken,
    rewardRateLimit,
    async (req, res) => {
        const userId = req.user.userId;

        const client = await db.connect();

        try {
            await client.query('BEGIN');

            await lockRewardOperation(
                client,
                userId,
                'game'
            );

            const usage =
                await getDailyUsage(
                    client,
                    userId
                );

            if (
                Number(usage.game_count) >=
                MAX_GAME_REWARDS_PER_DAY
            ) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        `Alcanzaste el máximo de ` +
                        `${MAX_GAME_REWARDS_PER_DAY} ` +
                        `recompensas de juego por día.`
                });
            }

            const active = await client.query(
                `SELECT session_id
                 FROM reward_sessions
                 WHERE user_id = $1
                   AND reward_type = 'game'
                   AND claimed_at IS NULL
                   AND expires_at > NOW()
                 LIMIT 1`,
                [String(userId)]
            );

            if (active.rows.length > 0) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    error:
                        'Ya tenés una sesión de juego en curso.'
                });
            }

            const recent = await client.query(
                `SELECT claimed_at
                 FROM reward_sessions
                 WHERE user_id = $1
                   AND reward_type = 'game'
                   AND claimed_at IS NOT NULL
                 ORDER BY claimed_at DESC
                 LIMIT 1`,
                [String(userId)]
            );

            if (recent.rows.length > 0) {
                const elapsed =
                    Date.now() -
                    new Date(
                        recent.rows[0].claimed_at
                    ).getTime();

                if (
                    elapsed <
                    GAME_COOLDOWN_MS
                ) {
                    const remaining =
                        Math.ceil(
                            (
                                GAME_COOLDOWN_MS -
                                elapsed
                            ) / 1000
                        );

                    await client.query('ROLLBACK');

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos ` +
                            `para volver a reclamar.`
                    });
                }
            }

            const sessionId =
                newRewardSessionId();

            const started = new Date();

            const expires =
                new Date(
                    started.getTime() +
                    REWARD_SESSION_MAX_AGE_MS
                );

            await client.query(
                `INSERT INTO reward_sessions
                    (
                        session_id,
                        user_id,
                        reward_type,
                        started_at,
                        expires_at
                    )
                 VALUES
                    ($1, $2, 'game', $3, $4)`,
                [
                    sessionId,
                    String(userId),
                    started,
                    expires
                ]
            );

            await client.query('COMMIT');

            return res.json({
                success: true,
                sessionId,
                waitSeconds: GAME_MIN_SECONDS
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error iniciando juego:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'No se pudo iniciar el juego.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// GAME - CLAIM
// ============================================================

app.post(
    '/api/v1/game/claim',
    verifyToken,
    rewardRateLimit,
    async (req, res) => {
        const {
            sessionId
        } = req.body || {};

        const userId = req.user.userId;

        if (
            typeof sessionId !== 'string' ||
            !/^[a-f0-9]{64}$/.test(sessionId)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Sesión de juego inválida.'
            });
        }

        const client = await db.connect();

        try {
            await client.query('BEGIN');

            await lockRewardOperation(
                client,
                userId,
                'game'
            );

            const sessionRes =
                await client.query(
                    `SELECT *
                     FROM reward_sessions
                     WHERE session_id = $1
                       AND user_id = $2
                       AND reward_type = 'game'
                     FOR UPDATE`,
                    [
                        sessionId,
                        String(userId)
                    ]
                );

            if (sessionRes.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Sesión de juego no encontrada.'
                });
            }

            const session =
                sessionRes.rows[0];

            if (session.claimed_at) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    error:
                        'Esta sesión ya fue reclamada.'
                });
            }

            const now = Date.now();

            const startedMs =
                new Date(
                    session.started_at
                ).getTime();

            const expiresMs =
                new Date(
                    session.expires_at
                ).getTime();

            if (
                now <
                startedMs +
                GAME_MIN_SECONDS * 1000
            ) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        `Todavía no pasaron ` +
                        `${GAME_MIN_SECONDS} segundos.`
                });
            }

            if (now > expiresMs) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        'La sesión de juego expiró. Iniciá otra.'
                });
            }

            const usage =
                await getDailyUsage(
                    client,
                    userId
                );

            if (
                Number(usage.game_count) >=
                MAX_GAME_REWARDS_PER_DAY
            ) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de juegos alcanzado.'
                });
            }

            const recentClaim =
                await client.query(
                    `SELECT claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'game'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [String(userId)]
                );

            if (recentClaim.rows.length > 0) {
                const elapsed =
                    now -
                    new Date(
                        recentClaim.rows[0].claimed_at
                    ).getTime();

                if (
                    elapsed <
                    GAME_COOLDOWN_MS
                ) {
                    await client.query('ROLLBACK');

                    const remaining =
                        Math.ceil(
                            (
                                GAME_COOLDOWN_MS -
                                elapsed
                            ) / 1000
                        );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos ` +
                            `para otra recompensa de juego.`
                    });
                }
            }

            // Incremento atómico y condicionado.
            const usageUpdate =
                await client.query(
                    `INSERT INTO reward_daily_usage
                        (
                            user_id,
                            reward_date,
                            video_count,
                            game_count
                        )
                     VALUES
                        ($1, CURRENT_DATE, 0, 1)
                     ON CONFLICT (user_id, reward_date)
                     DO UPDATE SET
                        game_count =
                            reward_daily_usage.game_count + 1
                     WHERE
                        reward_daily_usage.game_count <
                        $2
                     RETURNING game_count`,
                    [
                        String(userId),
                        MAX_GAME_REWARDS_PER_DAY
                    ]
                );

            if (usageUpdate.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de juegos alcanzado.'
                });
            }

            await client.query(
                `UPDATE reward_sessions
                 SET claimed_at = NOW()
                 WHERE session_id = $1`,
                [sessionId]
            );

            const balanceRes =
                await client.query(
                    `UPDATE web_users
                     SET points_balance =
                         points_balance + $1
                     WHERE id = $2
                     RETURNING points_balance`,
                    [
                        GAME_REWARD_POINTS,
                        userId
                    ]
                );

            if (balanceRes.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            await client.query('COMMIT');

            return res.json({
                success: true,
                pointsAwarded:
                    GAME_REWARD_POINTS,
                newBalance:
                    balanceRes.rows[0].points_balance
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error reclamando recompensa de juego:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error interno del servidor.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// REFERIDOS
// ============================================================

app.get(
    '/api/v1/user/referrals',
    verifyToken,
    async (req, res) => {
        try {
            const userId =
                req.user.userId;

            const userRes =
                await db.query(
                    `SELECT
                        referral_code,
                        total_referrals
                     FROM web_users
                     WHERE id = $1`,
                    [userId]
                );

            if (userRes.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            const {
                referral_code,
                total_referrals
            } = userRes.rows[0];

            const referralsRes =
                await db.query(
                    `SELECT
                        email,
                        created_at
                     FROM web_users
                     WHERE referred_by = $1
                     ORDER BY created_at DESC`,
                    [userId]
                );

            const referrals =
                referralsRes.rows.map(ref => {
                    const parts =
                        String(ref.email).split('@');

                    const name =
                        parts[0] || '';

                    const domain =
                        parts[1] || '';

                    const maskedName =
                        name.length > 2
                            ? `${name[0]}***${name[name.length - 1]}`
                            : `${name[0] || '*'}*`;

                    return {
                        email:
                            `${maskedName}@${domain}`,
                        created_at:
                            ref.created_at,
                        points_earned:
                            REFERRAL_BONUS
                    };
                });

            return res.json({
                success: true,
                referral_code,
                total_referrals:
                    Number(total_referrals) || 0,
                total_points_earned:
                    (
                        Number(total_referrals) || 0
                    ) * REFERRAL_BONUS,
                bonus_per_referral:
                    REFERRAL_BONUS,
                referrals
            });
        } catch (err) {
            console.error(
                'Error al obtener referidos:',
                err
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al consultar referidos.'
            });
        }
    }
);

// ============================================================
// RETIRO
// ============================================================

app.post(
    '/api/v1/withdraw',
    verifyToken,
    withdrawRateLimit,
    async (req, res) => {
        const {
            amount,
            payout_method,
            account_details
        } = req.body || {};

        const userId =
            req.user.userId;

        if (
            amount === undefined ||
            typeof payout_method !== 'string' ||
            typeof account_details !== 'string'
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Todos los campos son obligatorios.'
            });
        }

        const methodKey =
            normalizePayoutMethod(
                payout_method
            );

        if (!methodKey) {
            return res.status(400).json({
                success: false,
                error:
                    'Método de pago no válido.'
            });
        }

        const withdrawAmount =
            normalizeMoney(amount);

        if (
            withdrawAmount === null ||
            withdrawAmount <= 0
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Monto de retiro inválido.'
            });
        }

        // El campo de BD es NUMERIC(10,2).
        // Exigimos máximo dos decimales.
        if (
            Math.abs(
                Number(amount) -
                withdrawAmount
            ) > 0.0000001
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'El monto debe tener como máximo dos decimales.'
            });
        }

        const accountDetails =
            account_details.trim();

        if (
            accountDetails.length < 3 ||
            accountDetails.length > 500
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Los datos de la cuenta no son válidos.'
            });
        }

        const methodConfig =
            PAYOUT_CONFIG[methodKey];

        if (
            withdrawAmount <
            methodConfig.minAmount
        ) {
            return res.status(400).json({
                success: false,
                error:
                    `El monto mínimo de retiro es ` +
                    `$${methodConfig.minAmount.toFixed(2)} USD.`
            });
        }

        const userFee =
            (
                withdrawAmount *
                methodConfig.fixedFeePercent
            ) +
            methodConfig.fixedFeeAmount;

        const finalAmountToSend =
            Math.max(
                0,
                withdrawAmount - userFee
            );

        const pointsToDeduct =
            Math.round(
                withdrawAmount /
                POINT_TO_CURRENCY_RATIO
            );

        if (
            pointsToDeduct <= 0
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Monto de retiro inválido.'
            });
        }

        const client =
            await db.connect();

        try {
            await client.query('BEGIN');

            const userResult =
                await client.query(
                    `SELECT
                        points_balance
                     FROM web_users
                     WHERE id = $1
                     FOR UPDATE`,
                    [userId]
                );

            if (userResult.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            const totalPoints =
                Number(
                    userResult.rows[0]
                        .points_balance
                ) || 0;

            const availableBalanceUSD =
                totalPoints *
                POINT_TO_CURRENCY_RATIO;

            if (
                withdrawAmount >
                availableBalanceUSD
            ) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        'Saldo insuficiente en puntos.'
                });
            }

            // Guardamos el método normalizado y el importe neto
            // en el mismo campo utilizado actualmente por tu admin.
            const payoutDescription =
                `${methodKey} ` +
                `(Neto: $${finalAmountToSend.toFixed(2)} USD ` +
                `- Fee: $${userFee.toFixed(2)})`;

            const insertQuery = `
                INSERT INTO withdrawal_requests
                    (
                        user_id,
                        amount,
                        payout_method,
                        account_details
                    )
                VALUES
                    ($1, $2, $3, $4)
                RETURNING *;
            `;

            const newWithdrawal =
                await client.query(
                    insertQuery,
                    [
                        userId,
                        withdrawAmount,
                        payoutDescription,
                        accountDetails
                    ]
                );

            // Descuento dentro de la misma transacción.
            const balanceUpdate =
                await client.query(
                    `UPDATE web_users
                     SET points_balance =
                         points_balance - $1
                     WHERE id = $2
                       AND points_balance >= $1
                     RETURNING points_balance`,
                    [
                        pointsToDeduct,
                        userId
                    ]
                );

            if (
                balanceUpdate.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        'El saldo cambió antes de completar el retiro.'
                });
            }

            await client.query('COMMIT');

            return res.status(201).json({
                success: true,
                message:
                    'Solicitud de retiro registrada con éxito.',
                withdrawal:
                    newWithdrawal.rows[0],
                fee_applied:
                    userFee.toFixed(2),
                net_amount:
                    finalAmountToSend.toFixed(2),
                newBalance:
                    balanceUpdate.rows[0].points_balance
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error al procesar retiro:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error interno del servidor.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// HISTORIAL DE RETIROS
// ============================================================

app.get(
    '/api/withdrawals',
    verifyToken,
    async (req, res) => {
        try {
            const history =
                await db.query(
                    `SELECT *
                     FROM withdrawal_requests
                     WHERE user_id = $1
                     ORDER BY created_at DESC`,
                    [req.user.userId]
                );

            return res.json({
                success: true,
                withdrawals:
                    history.rows
            });
        } catch (error) {
            console.error(
                'Error al obtener retiros:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al consultar el historial.'
            });
        }
    }
);

// ============================================================
// PERFIL
// ============================================================

app.get(
    '/api/v1/user/profile',
    verifyToken,
    async (req, res) => {
        try {
            const userRes =
                await db.query(
                    `SELECT
                        id,
                        email,
                        binance_id,
                        country_code,
                        tier_level,
                        points_balance,
                        daily_videos_watched,
                        referral_code,
                        total_referrals
                     FROM web_users
                     WHERE id = $1`,
                    [req.user.userId]
                );

            if (
                userRes.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            return res.json({
                success: true,
                user:
                    userRes.rows[0]
            });
        } catch (err) {
            console.error(
                'Error obteniendo perfil:',
                err
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al obtener el perfil.'
            });
        }
    }
);

// ============================================================
// ADMIN - RETIROS PENDIENTES
// ============================================================

app.get(
    '/api/admin/withdrawals/pending',
    verifyAdmin,
    async (req, res) => {
        try {
            const query = `
                SELECT
                    w.*,
                    u.email,
                    u.binance_id
                FROM withdrawal_requests w
                LEFT JOIN web_users u
                    ON w.user_id = u.id
                WHERE w.status = 'pending'
                ORDER BY w.created_at DESC
            `;

            const result =
                await db.query(query);

            return res.json({
                success: true,
                withdrawals:
                    result.rows
            });
        } catch (error) {
            console.error(
                'Error obteniendo retiros pendientes:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error de consulta en base de datos.'
            });
        }
    }
);

// ============================================================
// ADMIN - ACTUALIZAR RETIRO
// ============================================================

app.patch(
    '/api/admin/withdrawals/:id',
    verifyAdmin,
    async (req, res) => {
        const {
            id
        } = req.params;

        const {
            status
        } = req.body || {};

        if (
            typeof id !== 'string' ||
            id.length < 10 ||
            id.length > 100
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'ID de retiro inválido.'
            });
        }

        if (
            !['completed', 'rejected']
                .includes(status)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Estado inválido. Debe ser completed o rejected.'
            });
        }

        const client =
            await db.connect();

        try {
            await client.query('BEGIN');

            const checkResult =
                await client.query(
                    `SELECT *
                     FROM withdrawal_requests
                     WHERE id = $1
                     FOR UPDATE`,
                    [id]
                );

            if (
                checkResult.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    error:
                        'Solicitud no encontrada.'
                });
            }

            const withdrawal =
                checkResult.rows[0];

            if (
                withdrawal.status !==
                'pending'
            ) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    success: false,
                    error:
                        `La solicitud ya fue procesada como: ` +
                        `${withdrawal.status}`
                });
            }

            const result =
                await client.query(
                    `UPDATE withdrawal_requests
                     SET status = $1
                     WHERE id = $2
                     RETURNING *`,
                    [
                        status,
                        id
                    ]
                );

            if (status === 'rejected') {
                const pointsToRefund =
                    Math.round(
                        Number(withdrawal.amount) /
                        POINT_TO_CURRENCY_RATIO
                    );

                await client.query(
                    `UPDATE web_users
                     SET points_balance =
                         points_balance + $1
                     WHERE id = $2`,
                    [
                        pointsToRefund,
                        withdrawal.user_id
                    ]
                );
            }

            await client.query('COMMIT');

            return res.json({
                success: true,
                message:
                    `Solicitud #${id} marcada como ${status}.`,
                withdrawal:
                    result.rows[0]
            });
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                'Error actualizando retiro:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al actualizar la solicitud.'
            });
        } finally {
            client.release();
        }
    }
);

// ============================================================
// 404
// ============================================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Ruta no encontrada.'
    });
});

// ============================================================
// MANEJO GLOBAL DE ERRORES
// ============================================================

app.use((err, req, res, next) => {
    console.error(
        'Error no controlado:',
        err
    );

    if (
        err &&
        err.message ===
        'Origen no permitido por CORS.'
    ) {
        return res.status(403).json({
            success: false,
            error:
                'Origen no permitido.'
        });
    }

    return res.status(500).json({
        success: false,
        error:
            'Error interno del servidor.'
    });
});

// ============================================================
// INICIALIZACIÓN
// ============================================================

async function startServer() {
    try {
        await db.query('SELECT 1');

        await ensureRewardTables();

        app.listen(PORT, () => {
            console.log(
                `Servidor iniciado correctamente en puerto ${PORT}.`
            );
        });
    } catch (error) {
        console.error(
            'No se pudo inicializar el servidor:',
            error
        );

        process.exit(1);
    }
}

startServer();
```
