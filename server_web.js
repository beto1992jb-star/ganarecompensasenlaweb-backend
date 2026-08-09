```javascript
require('dotenv').config();

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

const PORT = Number(process.env.PORT) || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

const CPX_APP_ID =
    process.env.CPX_APP_ID || '35135';

const VIDEO_AD_URL =
    process.env.VIDEO_AD_URL ||
    'https://omg10.com/4/11528482';

// ============================================================
// VALIDACIÓN DE VARIABLES DE ENTORNO
// ============================================================

if (
    !JWT_SECRET ||
    JWT_SECRET.length < 32
) {
    throw new Error(
        'JWT_SECRET es obligatorio y debe tener al menos 32 caracteres.'
    );
}

if (
    !ADMIN_SECRET ||
    ADMIN_SECRET.length < 32
) {
    throw new Error(
        'ADMIN_SECRET es obligatorio y debe tener al menos 32 caracteres.'
    );
}

if (!DATABASE_URL) {
    throw new Error(
        'DATABASE_URL es obligatorio.'
    );
}

if (
    !CPX_HASH_SECRET ||
    CPX_HASH_SECRET.length < 16
) {
    throw new Error(
        'CPX_HASH_SECRET es obligatorio y debe tener al menos 16 caracteres.'
    );
}

if (!ALLOWED_ORIGIN) {
    throw new Error(
        'ALLOWED_ORIGIN es obligatorio.'
    );
}

// ============================================================
// CONFIGURACIÓN DE NEGOCIO
// ============================================================

// 1000 puntos = 1 USD
const POINT_TO_CURRENCY_RATIO = 0.001;

const VIDEO_REWARD_POINTS = 5;
const GAME_REWARD_POINTS = 1;
const REFERRAL_BONUS = 25;

const MAX_VIDEO_REWARDS_PER_DAY = 5;
const MAX_GAME_REWARDS_PER_DAY = 20;

const VIDEO_COOLDOWN_MS =
    10 * 60 * 1000;

const GAME_COOLDOWN_MS =
    60 * 1000;

const VIDEO_MIN_SECONDS = 45;
const GAME_MIN_SECONDS = 60;

const REWARD_SESSION_MAX_AGE_MS =
    15 * 60 * 1000;

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
// EXPRESS
// ============================================================

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(
    express.json({
        limit: '20kb'
    })
);

// ============================================================
// HEADERS DE SEGURIDAD
// ============================================================

app.use((req, res, next) => {
    res.setHeader(
        'X-Content-Type-Options',
        'nosniff'
    );

    res.setHeader(
        'X-Frame-Options',
        'DENY'
    );

    res.setHeader(
        'Referrer-Policy',
        'strict-origin-when-cross-origin'
    );

    res.setHeader(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=()'
    );

    res.setHeader(
        'Cross-Origin-Opener-Policy',
        'same-origin'
    );

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
    origin(origin, callback) {
        // Health checks y algunas herramientas no envían Origin.
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(
            new Error(
                'Origen no permitido por CORS.'
            )
        );
    },

    methods: [
        'GET',
        'POST',
        'PATCH',
        'OPTIONS'
    ],

    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Accept',
        'X-Requested-With',
        'x-admin-secret'
    ],

    credentials: false,

    optionsSuccessStatus: 204
};

app.use(
    cors(corsOptions)
);

// ============================================================
// RATE LIMITER
// ============================================================

const rateLimitStores = new Map();

function getClientIp(req) {
    const forwarded =
        req.headers['x-forwarded-for'];

    if (typeof forwarded === 'string') {
        return forwarded
            .split(',')[0]
            .trim();
    }

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        'unknown'
    );
}

function rateLimit({
    windowMs,
    max,
    keyPrefix,
    message
}) {
    return (req, res, next) => {
        const ip = getClientIp(req);

        const key =
            `${keyPrefix}:${ip}`;

        const now = Date.now();

        let record =
            rateLimitStores.get(key);

        if (
            !record ||
            now >= record.resetAt
        ) {
            record = {
                count: 0,
                resetAt:
                    now + windowMs
            };
        }

        record.count += 1;

        rateLimitStores.set(
            key,
            record
        );

        res.setHeader(
            'X-RateLimit-Limit',
            String(max)
        );

        res.setHeader(
            'X-RateLimit-Remaining',
            String(
                Math.max(
                    0,
                    max - record.count
                )
            )
        );

        if (record.count > max) {
            res.setHeader(
                'Retry-After',
                String(
                    Math.ceil(
                        (
                            record.resetAt -
                            now
                        ) / 1000
                    )
                )
            );

            return res.status(429).json({
                success: false,
                error:
                    message ||
                    'Demasiadas solicitudes. Intentá nuevamente más tarde.'
            });
        }

        next();
    };
}

setInterval(() => {
    const now = Date.now();

    for (
        const [key, record]
        of rateLimitStores.entries()
    ) {
        if (
            now >= record.resetAt
        ) {
            rateLimitStores.delete(key);
        }
    }
}, 10 * 60 * 1000).unref();

const authRateLimit = rateLimit({
    windowMs:
        15 * 60 * 1000,
    max: 15,
    keyPrefix: 'auth',
    message:
        'Demasiados intentos. Esperá unos minutos antes de volver a intentar.'
});

const rewardRateLimit = rateLimit({
    windowMs:
        60 * 1000,
    max: 30,
    keyPrefix: 'reward'
});

const withdrawRateLimit = rateLimit({
    windowMs:
        10 * 60 * 1000,
    max: 10,
    keyPrefix: 'withdraw'
});

const cpxRateLimit = rateLimit({
    windowMs:
        60 * 1000,
    max: 30,
    keyPrefix: 'cpx'
});

// ============================================================
// POSTGRESQL
// ============================================================

const db = new Pool({
    connectionString:
        DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    },

    max: 10,

    idleTimeoutMillis:
        30000,

    connectionTimeoutMillis:
        10000,

    application_name:
        'ganarecompensasenlaweb-backend'
});

db.on(
    'error',
    err => {
        console.error(
            'Error inesperado en cliente inactivo de PostgreSQL:',
            err
        );
    }
);

// ============================================================
// AUXILIARES
// ============================================================

function normalizeEmail(email) {
    return String(email || '')
        .trim()
        .toLowerCase();
}

function isValidEmail(email) {
    if (
        typeof email !== 'string'
    ) {
        return false;
    }

    if (
        email.length < 5 ||
        email.length > 255
    ) {
        return false;
    }

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}

function normalizeCountryCode(
    countryCode
) {
    const value =
        String(
            countryCode || 'AR'
        )
            .trim()
            .toUpperCase();

    if (
        /^[A-Z]{2}$/.test(value)
    ) {
        return value;
    }

    return null;
}

function normalizeReferralCode(
    code
) {
    return String(code || '')
        .trim()
        .toUpperCase();
}

function normalizePayoutMethod(
    method
) {
    const value =
        String(method || '')
            .trim()
            .toLowerCase();

    if (
        value === 'paypal' ||
        value.includes('paypal')
    ) {
        return 'paypal';
    }

    if (
        value === 'mercadopago' ||
        value === 'mercado pago' ||
        value.includes('mercadopago')
    ) {
        return 'mercadopago';
    }

    if (
        value === 'binance' ||
        value.includes('binance')
    ) {
        return 'binance';
    }

    return null;
}

function normalizeMoney(value) {
    const number =
        Number(value);

    if (
        !Number.isFinite(number)
    ) {
        return null;
    }

    return Math.round(
        number * 100
    ) / 100;
}

function newRewardSessionId() {
    return crypto
        .randomBytes(32)
        .toString('hex');
}

function isValidUUID(value) {
    return typeof value === 'string' &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
            .test(value);
}

function isValidRewardSessionId(
    value
) {
    return (
        typeof value === 'string' &&
        /^[a-f0-9]{64}$/.test(value)
    );
}

function safeRollback(client) {
    return client
        .query('ROLLBACK')
        .catch(() => {});
}

// ============================================================
// LOCK DE RECOMPENSA
// ============================================================

async function lockRewardOperation(
    client,
    userId,
    rewardType
) {
    const key =
        `${String(userId)}:${String(rewardType)}`;

    await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [key]
    );
}

// ============================================================
// USO DIARIO
// ============================================================

async function getDailyUsage(
    client,
    userId
) {
    const result =
        await client.query(
            `SELECT
                video_count,
                game_count
             FROM reward_daily_usage
             WHERE user_id = $1
               AND reward_date = CURRENT_DATE`,
            [userId]
        );

    if (
        result.rows.length === 0
    ) {
        return {
            video_count: 0,
            game_count: 0
        };
    }

    return result.rows[0];
}

// ============================================================
// EVENTO DE RECOMPENSA
// ============================================================

async function insertRewardEvent(
    client,
    {
        userId,
        sourceType,
        transId,
        points
    }
) {
    const result =
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
             ON CONFLICT (trans_id)
             DO NOTHING
             RETURNING id`,
            [
                userId,
                sourceType,
                transId,
                points
            ]
        );

    return (
        result.rows.length > 0
    );
}

// ============================================================
// TABLAS AUXILIARES
// ============================================================

async function ensureRewardTables() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS reward_sessions (
            session_id TEXT PRIMARY KEY,
            user_id UUID NOT NULL,
            reward_type TEXT NOT NULL
                CHECK (
                    reward_type IN ('video', 'game')
                ),
            started_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            claimed_at TIMESTAMPTZ NULL
        );

        CREATE TABLE IF NOT EXISTS reward_daily_usage (
            user_id UUID NOT NULL,
            reward_date DATE NOT NULL,
            video_count INTEGER NOT NULL DEFAULT 0,
            game_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (
                user_id,
                reward_date
            )
        );
    `);

    // Índices.
    await db.query(`
        CREATE INDEX IF NOT EXISTS
        idx_reward_sessions_user_type
        ON reward_sessions(
            user_id,
            reward_type
        );

        CREATE INDEX IF NOT EXISTS
        idx_reward_sessions_claimed
        ON reward_sessions(
            user_id,
            reward_type,
            claimed_at
        );

        CREATE INDEX IF NOT EXISTS
        idx_reward_sessions_expiry
        ON reward_sessions(
            expires_at
        );
    `);

    // Intentar garantizar FK en reward_sessions.
    await db.query(`
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname =
                    'reward_sessions_user_id_fkey'
            ) THEN
                ALTER TABLE reward_sessions
                ADD CONSTRAINT
                    reward_sessions_user_id_fkey
                FOREIGN KEY (user_id)
                REFERENCES web_users(id)
                ON DELETE CASCADE;
            END IF;
        END $$;
    `);

    // FK de reward_daily_usage.
    await db.query(`
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname =
                    'reward_daily_usage_user_id_fkey'
            ) THEN
                ALTER TABLE reward_daily_usage
                ADD CONSTRAINT
                    reward_daily_usage_user_id_fkey
                FOREIGN KEY (user_id)
                REFERENCES web_users(id)
                ON DELETE CASCADE;
            END IF;
        END $$;
    `);

    // Limpiar sesiones expiradas antiguas.
    await db.query(`
        DELETE FROM reward_sessions
        WHERE expires_at <
            NOW() - INTERVAL '2 days'
    `);
}

// ============================================================
// JWT
// ============================================================

function createUserToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email
        },
        JWT_SECRET,
        {
            expiresIn: '7d',
            issuer:
                'ganarecompensasenlaweb'
        }
    );
}

const verifyToken = (
    req,
    res,
    next
) => {
    const authHeader =
        req.headers.authorization;

    if (
        !authHeader ||
        typeof authHeader !== 'string' ||
        !authHeader.startsWith(
            'Bearer '
        )
    ) {
        return res.status(401).json({
            success: false,
            error:
                'Acceso denegado. Token no provisto.'
        });
    }

    const token =
        authHeader
            .slice(7)
            .trim();

    if (!token) {
        return res.status(401).json({
            success: false,
            error:
                'Token no provisto.'
        });
    }

    try {
        const decoded =
            jwt.verify(
                token,
                JWT_SECRET,
                {
                    issuer:
                        'ganarecompensasenlaweb'
                }
            );

        if (
            !decoded ||
            !decoded.userId ||
            !isValidUUID(
                String(decoded.userId)
            )
        ) {
            return res.status(403).json({
                success: false,
                error:
                    'Token inválido.'
            });
        }

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            error:
                'Token inválido o expirado.'
        });
    }
};

// ============================================================
// ADMIN
// ============================================================

const verifyAdmin = (
    req,
    res,
    next
) => {
    const provided =
        req.headers['x-admin-secret'];

    if (
        typeof provided !== 'string' ||
        provided.length === 0
    ) {
        return res.status(401).json({
            success: false,
            error:
                'No autorizado.'
        });
    }

    const providedBuffer =
        Buffer.from(provided);

    const expectedBuffer =
        Buffer.from(ADMIN_SECRET);

    if (
        providedBuffer.length !==
        expectedBuffer.length
    ) {
        return res.status(401).json({
            success: false,
            error:
                'No autorizado.'
        });
    }

    if (
        !crypto.timingSafeEqual(
            providedBuffer,
            expectedBuffer
        )
    ) {
        return res.status(401).json({
            success: false,
            error:
                'No autorizado.'
        });
    }

    next();
};

// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
    '/',
    async (req, res) => {
        return res.status(200).json({
            success: true,
            message:
                'Servidor activo',
            status: 'ok'
        });
    }
);

app.get(
    '/health',
    async (req, res) => {
        try {
            await db.query(
                'SELECT 1'
            );

            return res.status(200).json({
                success: true,
                status: 'ok',
                database: 'connected'
            });
        } catch (error) {
            return res.status(503).json({
                success: false,
                status: 'error',
                database:
                    'unavailable'
            });
        }
    }
);

// ============================================================
// CPX - SURVEY URL
// ============================================================

app.get(
    '/api/v1/cpx/survey-url',
    verifyToken,
    cpxRateLimit,
    async (req, res) => {
        try {
            const result =
                await db.query(
                    `SELECT
                        id,
                        email,
                        country_code
                     FROM web_users
                     WHERE id = $1`,
                    [req.user.userId]
                );

            if (
                result.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            const user =
                result.rows[0];

            const userId =
                String(user.id);

            const secureHash =
                crypto
                    .createHash('md5')
                    .update(
                        `${userId}-${CPX_HASH_SECRET}`
                    )
                    .digest('hex');

            const params =
                new URLSearchParams({
                    app_id:
                        String(CPX_APP_ID),

                    ext_user_id:
                        userId,

                    secure_hash:
                        secureHash,

                    username:
                        user.email,

                    email:
                        user.email,

                    user_country_code:
                        user.country_code ||
                        'AR'
                });

            return res.json({
                success: true,
                url:
                    `https://offers.cpx-research.com/index.php?${params.toString()}`
            });
        } catch (error) {
            console.error(
                'Error generando URL CPX:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'No se pudo preparar CPX Research.'
            });
        }
    }
);

// ============================================================
// CPX POSTBACK
// ============================================================

app.get(
    '/api/cpx-postback',
    async (req, res) => {
        const {
            user_id,
            amount_usd,
            trans_id,
            status,
            hash
        } = req.query;

        // CPX recibe OK para evitar reintentos
        // innecesarios de parámetros inválidos.
        if (
            !user_id ||
            !trans_id ||
            status === undefined ||
            status === null ||
            !hash
        ) {
            return res
                .status(200)
                .send('OK');
        }

        if (
            !isValidUUID(
                String(user_id)
            )
        ) {
            return res
                .status(200)
                .send('OK');
        }

        const transactionId =
            String(trans_id)
                .trim();

        if (
            transactionId.length < 1 ||
            transactionId.length > 128
        ) {
            return res
                .status(200)
                .send('OK');
        }

        const computedHash =
            crypto
                .createHash('md5')
                .update(
                    `${transactionId}-${CPX_HASH_SECRET}`
                )
                .digest('hex');

        const receivedHash =
            String(hash)
                .trim()
                .toLowerCase();

        if (
            computedHash !==
            receivedHash
        ) {
            console.error(
                'Firma HASH de CPX inválida.'
            );

            return res
                .status(200)
                .send('OK');
        }

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

            const userCheck =
                await client.query(
                    `SELECT id
                     FROM web_users
                     WHERE id = $1`,
                    [user_id]
                );

            if (
                userCheck.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

                return res
                    .status(200)
                    .send('OK');
            }

            // =================================================
            // COMPLETADA
            // =================================================

            if (
                String(status) === '1'
            ) {
                const amount =
                    Number(amount_usd);

                if (
                    !Number.isFinite(amount) ||
                    amount <= 0 ||
                    amount > 100000
                ) {
                    await safeRollback(
                        client
                    );

                    return res
                        .status(200)
                        .send('OK');
                }

                const points =
                    Math.round(
                        amount /
                        POINT_TO_CURRENCY_RATIO
                    );

                if (
                    points <= 0
                ) {
                    await safeRollback(
                        client
                    );

                    return res
                        .status(200)
                        .send('OK');
                }

                // Primero intentamos crear el evento.
                // Esto garantiza idempotencia.
                const eventInserted =
                    await insertRewardEvent(
                        client,
                        {
                            userId:
                                user_id,

                            sourceType:
                                'CPX_RESEARCH',

                            transId:
                                transactionId,

                            points
                        }
                    );

                if (
                    eventInserted
                ) {
                    const balance =
                        await client.query(
                            `UPDATE web_users
                             SET points_balance =
                                 points_balance + $1
                             WHERE id = $2
                             RETURNING id`,
                            [
                                points,
                                user_id
                            ]
                        );

                    if (
                        balance.rows.length === 0
                    ) {
                        throw new Error(
                            'No se pudo actualizar el saldo CPX.'
                        );
                    }
                }
            }

            // =================================================
            // REVERSIÓN
            // =================================================

            else if (
                String(status) === '2'
            ) {
                const original =
                    await client.query(
                        `SELECT
                            user_id,
                            points_awarded
                         FROM web_reward_events
                         WHERE trans_id = $1
                           AND source_type =
                               'CPX_RESEARCH'
                         LIMIT 1`,
                        [transactionId]
                    );

                if (
                    original.rows.length > 0 &&
                    String(
                        original.rows[0].user_id
                    ) === String(user_id)
                ) {
                    const points =
                        Math.abs(
                            Number(
                                original.rows[0]
                                    .points_awarded
                            ) || 0
                        );

                    if (
                        points > 0
                    ) {
                        const reversalId =
                            `${transactionId}_REV`;

                        const reversalInserted =
                            await insertRewardEvent(
                                client,
                                {
                                    userId:
                                        user_id,

                                    sourceType:
                                        'CPX_RESEARCH_REVERSED',

                                    transId:
                                        reversalId,

                                    points:
                                        -points
                                }
                            );

                        if (
                            reversalInserted
                        ) {
                            const balance =
                                await client.query(
                                    `UPDATE web_users
                                     SET points_balance =
                                         GREATEST(
                                             0,
                                             points_balance - $1
                                         )
                                     WHERE id = $2
                                     RETURNING id`,
                                    [
                                        points,
                                        user_id
                                    ]
                                );

                            if (
                                balance.rows.length === 0
                            ) {
                                throw new Error(
                                    'No se pudo actualizar el saldo por reversión CPX.'
                                );
                            }
                        }
                    }
                }
            }

            await client.query(
                'COMMIT'
            );

            return res
                .status(200)
                .send('OK');
        } catch (error) {
            await safeRollback(
                client
            );

            console.error(
                'Error procesando postback CPX:',
                error
            );

            return res
                .status(200)
                .send('OK');
        } finally {
            client.release();
        }
    }
);

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
                error:
                    'Email y contraseña requeridos.'
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

        if (
            !isValidEmail(
                normalizedEmail
            )
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'El correo electrónico no es válido.'
            });
        }

        if (
            password.length < 8 ||
            password.length > 128
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'La contraseña debe tener entre 8 y 128 caracteres.'
            });
        }

        const userCountry =
            normalizeCountryCode(
                country_code
            );

        if (!userCountry) {
            return res.status(400).json({
                success: false,
                error:
                    'Código de país inválido.'
            });
        }

        const referralCode =
            normalizeReferralCode(
                referral_code
            );

        if (
            referralCode &&
            !/^[A-Z0-9_-]{3,20}$/
                .test(referralCode)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Código de referido inválido.'
            });
        }

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

            // Bloqueo sobre el email.
            await client.query(
                `SELECT
                    pg_advisory_xact_lock(
                        hashtext($1)
                    )`,
                [
                    `register:${normalizedEmail}`
                ]
            );

            const checkUser =
                await client.query(
                    `SELECT id
                     FROM web_users
                     WHERE email = $1`,
                    [normalizedEmail]
                );

            if (
                checkUser.rows.length > 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(400).json({
                    success: false,
                    error:
                        'El correo electrónico ya está registrado.'
                });
            }

            let referrerId = null;

            if (referralCode) {
                const referrerCheck =
                    await client.query(
                        `SELECT id
                         FROM web_users
                         WHERE referral_code = $1
                         LIMIT 1`,
                        [referralCode]
                    );

                if (
                    referrerCheck.rows.length > 0
                ) {
                    referrerId =
                        referrerCheck.rows[0].id;
                }
            }

            // Generar código único.
            let myReferralCode = null;

            for (
                let attempt = 0;
                attempt < 10;
                attempt++
            ) {
                const candidate =
                    crypto
                        .randomBytes(8)
                        .toString('hex')
                        .toUpperCase()
                        .slice(0, 16);

                const exists =
                    await client.query(
                        `SELECT 1
                         FROM web_users
                         WHERE referral_code = $1
                         LIMIT 1`,
                        [candidate]
                    );

                if (
                    exists.rows.length === 0
                ) {
                    myReferralCode =
                        candidate;
                    break;
                }
            }

            if (!myReferralCode) {
                throw new Error(
                    'No se pudo generar un código de referido único.'
                );
            }

            const hashedPassword =
                await bcrypt.hash(
                    password,
                    12
                );

            const newUser =
                await client.query(
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

            const user =
                newUser.rows[0];

            // Bono de referido.
            if (referrerId) {
                const referralTransactionId =
                    `REF_${user.id}_${crypto
                        .randomBytes(8)
                        .toString('hex')}`;

                const eventInserted =
                    await insertRewardEvent(
                        client,
                        {
                            userId:
                                referrerId,

                            sourceType:
                                'REFERRAL_BONUS',

                            transId:
                                referralTransactionId,

                            points:
                                REFERRAL_BONUS
                        }
                    );

                if (
                    eventInserted
                ) {
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
                }
            }

            await client.query(
                'COMMIT'
            );

            const token =
                createUserToken(
                    user
                );

            return res.json({
                success: true,
                user,
                token
            });
        } catch (error) {
            await safeRollback(
                client
            );

            // Error de UNIQUE.
            if (
                error.code === '23505'
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        'El correo electrónico o código de referido ya existe.'
                });
            }

            console.error(
                'Error en registro:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al registrar el usuario.'
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
                error:
                    'Email y contraseña requeridos.'
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

        if (
            !isValidEmail(
                normalizedEmail
            )
        ) {
            return res.status(401).json({
                success: false,
                error:
                    'Credenciales incorrectas.'
            });
        }

        if (
            password.length === 0 ||
            password.length > 128
        ) {
            return res.status(401).json({
                success: false,
                error:
                    'Credenciales incorrectas.'
            });
        }

        try {
            const userRes =
                await db.query(
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
                !userRes.rows[0]
                    .password_hash
            ) {
                return res.status(401).json({
                    success: false,
                    error:
                        'Credenciales incorrectas.'
                });
            }

            const user =
                userRes.rows[0];

            const validPassword =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!validPassword) {
                return res.status(401).json({
                    success: false,
                    error:
                        'Credenciales incorrectas.'
                });
            }

            delete user.password_hash;

            const token =
                createUserToken(
                    user
                );

            return res.json({
                success: true,
                user,
                token
            });
        } catch (error) {
            console.error(
                'Error en login:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error al iniciar sesión.'
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
            const result =
                await db.query(
                    `SELECT
                        points_balance
                     FROM web_users
                     WHERE id = $1`,
                    [req.user.userId]
                );

            if (
                result.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            return res.json({
                success: true,
                balance:
                    result.rows[0]
                        .points_balance
            });
        } catch (error) {
            console.error(
                'Error obteniendo saldo:',
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    'Error del servidor.'
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
        const userId =
            req.user.userId;

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

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
                Number(
                    usage.video_count
                ) >=
                MAX_VIDEO_REWARDS_PER_DAY
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        `Alcanzaste el máximo de ${MAX_VIDEO_REWARDS_PER_DAY} recompensas de video por día.`
                });
            }

            const recent =
                await client.query(
                    `SELECT
                        claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'video'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [userId]
                );

            if (
                recent.rows.length > 0
            ) {
                const elapsed =
                    Date.now() -
                    new Date(
                        recent.rows[0]
                            .claimed_at
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

                    await safeRollback(
                        client
                    );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos para otro anuncio.`
                    });
                }
            }

            const active =
                await client.query(
                    `SELECT
                        session_id
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'video'
                       AND claimed_at IS NULL
                       AND expires_at > NOW()
                     LIMIT 1`,
                    [userId]
                );

            if (
                active.rows.length > 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(409).json({
                    success: false,
                    error:
                        'Ya tenés una sesión de video en curso.'
                });
            }

            const sessionId =
                newRewardSessionId();

            const started =
                new Date();

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
                    userId,
                    started,
                    expires
                ]
            );

            await client.query(
                'COMMIT'
            );

            return res.json({
                success: true,
                sessionId,
                waitSeconds:
                    VIDEO_MIN_SECONDS,
                adUrl:
                    VIDEO_AD_URL
            });
        } catch (error) {
            await safeRollback(
                client
            );

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

        const userId =
            req.user.userId;

        if (
            !isValidRewardSessionId(
                sessionId
            )
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Sesión de recompensa inválida.'
            });
        }

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

            await lockRewardOperation(
                client,
                userId,
                'video'
            );

            const sessionRes =
                await client.query(
                    `SELECT *
                     FROM reward_sessions
                     WHERE session_id = $1
                       AND user_id = $2
                       AND reward_type = 'video'
                     FOR UPDATE`,
                    [
                        sessionId,
                        userId
                    ]
                );

            if (
                sessionRes.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(404).json({
                    success: false,
                    error:
                        'Sesión de recompensa no encontrada.'
                });
            }

            const session =
                sessionRes.rows[0];

            if (
                session.claimed_at
            ) {
                await safeRollback(
                    client
                );

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

            const now =
                Date.now();

            if (
                now <
                startedMs +
                VIDEO_MIN_SECONDS * 1000
            ) {
                await safeRollback(
                    client
                );

                return res.status(400).json({
                    success: false,
                    error:
                        `Todavía no pasaron ${VIDEO_MIN_SECONDS} segundos.`
                });
            }

            if (
                now > expiresMs
            ) {
                await safeRollback(
                    client
                );

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
                Number(
                    usage.video_count
                ) >=
                MAX_VIDEO_REWARDS_PER_DAY
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de videos alcanzado.'
                });
            }

            const recentClaim =
                await client.query(
                    `SELECT
                        claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'video'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [userId]
                );

            if (
                recentClaim.rows.length > 0
            ) {
                const elapsed =
                    now -
                    new Date(
                        recentClaim.rows[0]
                            .claimed_at
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

                    await safeRollback(
                        client
                    );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos para otra recompensa de video.`
                    });
                }
            }

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
                     ON CONFLICT (
                        user_id,
                        reward_date
                     )
                     DO UPDATE SET
                        video_count =
                            reward_daily_usage.video_count + 1
                     WHERE
                        reward_daily_usage.video_count <
                        $2
                     RETURNING video_count`,
                    [
                        userId,
                        MAX_VIDEO_REWARDS_PER_DAY
                    ]
                );

            if (
                usageUpdate.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de videos alcanzado.'
                });
            }

            const rewardTransactionId =
                `VIDEO_${sessionId}`;

            const eventInserted =
                await insertRewardEvent(
                    client,
                    {
                        userId,
                        sourceType:
                            'WEB_VIDEO',
                        transId:
                            rewardTransactionId,
                        points:
                            VIDEO_REWARD_POINTS
                    }
                );

            if (
                !eventInserted
            ) {
                await safeRollback(
                    client
                );

                return res.status(409).json({
                    success: false,
                    error:
                        'Esta recompensa ya fue procesada.'
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

            if (
                balanceRes.rows.length === 0
            ) {
                throw new Error(
                    'Usuario no encontrado al acreditar video.'
                );
            }

            await client.query(
                'COMMIT'
            );

            return res.json({
                success: true,
                pointsAwarded:
                    VIDEO_REWARD_POINTS,
                newBalance:
                    balanceRes.rows[0]
                        .points_balance
            });
        } catch (error) {
            await safeRollback(
                client
            );

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
        const userId =
            req.user.userId;

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

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
                Number(
                    usage.game_count
                ) >=
                MAX_GAME_REWARDS_PER_DAY
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        `Alcanzaste el máximo de ${MAX_GAME_REWARDS_PER_DAY} recompensas de juego por día.`
                });
            }

            const active =
                await client.query(
                    `SELECT
                        session_id
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'game'
                       AND claimed_at IS NULL
                       AND expires_at > NOW()
                     LIMIT 1`,
                    [userId]
                );

            if (
                active.rows.length > 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(409).json({
                    success: false,
                    error:
                        'Ya tenés una sesión de juego en curso.'
                });
            }

            const recent =
                await client.query(
                    `SELECT
                        claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'game'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [userId]
                );

            if (
                recent.rows.length > 0
            ) {
                const elapsed =
                    Date.now() -
                    new Date(
                        recent.rows[0]
                            .claimed_at
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

                    await safeRollback(
                        client
                    );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos para volver a reclamar.`
                    });
                }
            }

            const sessionId =
                newRewardSessionId();

            const started =
                new Date();

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
                    userId,
                    started,
                    expires
                ]
            );

            await client.query(
                'COMMIT'
            );

            return res.json({
                success: true,
                sessionId,
                waitSeconds:
                    GAME_MIN_SECONDS
            });
        } catch (error) {
            await safeRollback(
                client
            );

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

        const userId =
            req.user.userId;

        if (
            !isValidRewardSessionId(
                sessionId
            )
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Sesión de juego inválida.'
            });
        }

        const client =
            await db.connect();

        try {
            await client.query(
                'BEGIN'
            );

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
                        userId
                    ]
                );

            if (
                sessionRes.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(404).json({
                    success: false,
                    error:
                        'Sesión de juego no encontrada.'
                });
            }

            const session =
                sessionRes.rows[0];

            if (
                session.claimed_at
            ) {
                await safeRollback(
                    client
                );

                return res.status(409).json({
                    success: false,
                    error:
                        'Esta sesión ya fue reclamada.'
                });
            }

            const now =
                Date.now();

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
                await safeRollback(
                    client
                );

                return res.status(400).json({
                    success: false,
                    error:
                        `Todavía no pasaron ${GAME_MIN_SECONDS} segundos.`
                });
            }

            if (
                now > expiresMs
            ) {
                await safeRollback(
                    client
                );

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
                Number(
                    usage.game_count
                ) >=
                MAX_GAME_REWARDS_PER_DAY
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de juegos alcanzado.'
                });
            }

            const recentClaim =
                await client.query(
                    `SELECT
                        claimed_at
                     FROM reward_sessions
                     WHERE user_id = $1
                       AND reward_type = 'game'
                       AND claimed_at IS NOT NULL
                     ORDER BY claimed_at DESC
                     LIMIT 1`,
                    [userId]
                );

            if (
                recentClaim.rows.length > 0
            ) {
                const elapsed =
                    now -
                    new Date(
                        recentClaim.rows[0]
                            .claimed_at
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

                    await safeRollback(
                        client
                    );

                    return res.status(429).json({
                        success: false,
                        error:
                            `Esperá ${remaining} segundos para otra recompensa de juego.`
                    });
                }
            }

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
                     ON CONFLICT (
                        user_id,
                        reward_date
                     )
                     DO UPDATE SET
                        game_count =
                            reward_daily_usage.game_count + 1
                     WHERE
                        reward_daily_usage.game_count <
                        $2
                     RETURNING game_count`,
                    [
                        userId,
                        MAX_GAME_REWARDS_PER_DAY
                    ]
                );

            if (
                usageUpdate.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

                return res.status(429).json({
                    success: false,
                    error:
                        'Límite diario de juegos alcanzado.'
                });
            }

            const rewardTransactionId =
                `GAME_${sessionId}`;

            const eventInserted =
                await insertRewardEvent(
                    client,
                    {
                        userId,
                        sourceType:
                            'WEB_GAME',
                        transId:
                            rewardTransactionId,
                        points:
                            GAME_REWARD_POINTS
                    }
                );

            if (
                !eventInserted
            ) {
                await safeRollback(
                    client
                );

                return res.status(409).json({
                    success: false,
                    error:
                        'Esta recompensa ya fue procesada.'
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

            if (
                balanceRes.rows.length === 0
            ) {
                throw new Error(
                    'Usuario no encontrado al acreditar juego.'
                );
            }

            await client.query(
                'COMMIT'
            );

            return res.json({
                success: true,
                pointsAwarded:
                    GAME_REWARD_POINTS,
                newBalance:
                    balanceRes.rows[0]
                        .points_balance
            });
        } catch (error) {
            await safeRollback(
                client
            );

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

            if (
                userRes.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    error:
                        'Usuario no encontrado.'
                });
            }

            const user =
                userRes.rows[0];

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
                referralsRes.rows.map(
                    ref => {
                        const parts =
                            String(
                                ref.email
                            ).split('@');

                        const name =
                            parts[0] || '';

                        const domain =
                            parts[1] || '';

                        let maskedName;

                        if (
                            name.length > 2
                        ) {
                            maskedName =
                                `${name[0]}***${name[name.length - 1]}`;
                        } else {
                            maskedName =
                                `${name[0] || '*'}*`;
                        }

                        return {
                            email:
                                `${maskedName}@${domain}`,

                            created_at:
                                ref.created_at,

                            points_earned:
                                REFERRAL_BONUS
                        };
                    }
                );

            const totalReferrals =
                Number(
                    user.total_referrals
                ) || 0;

            return res.json({
                success: true,

                referral_code:
                    user.referral_code,

                total_referrals:
                    totalReferrals,

                total_points_earned:
                    totalReferrals *
                    REFERRAL_BONUS,

                bonus_per_referral:
                    REFERRAL_BONUS,

                referrals
            });
        } catch (error) {
            console.error(
                'Error al obtener referidos:',
                error
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

        if (
            withdrawAmount >
            99999999.99
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Monto de retiro demasiado alto.'
            });
        }

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
            PAYOUT_CONFIG[
                methodKey
            ];

        if (
            withdrawAmount <
            methodConfig.minAmount
        ) {
            return res.status(400).json({
                success: false,
                error:
                    `El monto mínimo de retiro es $${methodConfig.minAmount.toFixed(2)} USD.`
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
                withdrawAmount -
                userFee
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
            await client.query(
                'BEGIN'
            );

            const userResult =
                await client.query(
                    `SELECT
                        points_balance
                     FROM web_users
                     WHERE id = $1
                     FOR UPDATE`,
                    [userId]
                );

            if (
                userResult.rows.length === 0
            ) {
                await safeRollback(
                    client
                );

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

            if (
                totalPoints <
                pointsToDeduct
            ) {
                await safeRollback(
                    client
                );

                return res.status(400).json({
                    success: false,
                    error:
                        'Saldo insuficiente en puntos.'
                });
            }

            const payoutDescription =
                `${methodKey} ` +
                `(Neto: $${finalAmountToSend.toFixed(2)} USD - Fee: $${userFee.toFixed(2)})`;

            const withdrawal =
                await client.query(
                    `INSERT INTO withdrawal_requests
                        (
                            user_id,
                            amount,
                            payout_method,
                            account_details,
                            status
                        )
                     VALUES
                        ($1, $2, $3, $4, 'pending')
                     RETURNING *`,
                    [
                        userId,
                        withdrawAmount,
                        payoutDescription,
                        accountDetails
                    ]
                );

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
                throw new Error(
                    'El saldo cambió antes de completar el retiro.'
                );
            }

            const withdrawalId =
                withdrawal.rows[0].id;

            await insertRewardEvent(
                client,
                {
                    userId,

                    sourceType:
                        'WITHDRAWAL',

                    transId:
                        `WITHDRAWAL_${withdrawalId}`,

                    points:
                        -pointsToDeduct
                }
            );

            await client.query(
                'COMMIT'
            );

            return res.status(201).json({
                success: true,

                message:
                    'Solicitud de retiro registrada con éxito.',

                withdrawal:
                    withdrawal.rows[0],

                fee_applied:
                    userFee.toFixed(2),

                net_amount:
                    finalAmountToSend.toFixed(2),

                newBalance:
                    balanceUpdate.rows[0]
                        .points_balance
            });
        } catch (error) {
            await safeRollback(
                client
            );

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
        } catch (error) {
            console.error(
                'Error obteniendo perfil:',
                error
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
            const result =
                await db.query(
                    `SELECT
                        w.*,
                        u.email,
                        u.binance_id
                     FROM withdrawal_requests w
                     LEFT JOIN web_users u
                        ON w.user_id = u.id
                     WHERE w.status = 'pending'
                     ORDER BY w.created_at DESC`
                );

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
            !isValidUUID(id)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'ID de retiro inválido.'
            });
        }

        if (
            ![
                'completed',
                'rejected'
            ].includes(status)
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
            await client.query(
                'BEGIN'
            );

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
                await safeRollback(
                    client
                );

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
                await safeRollback(
                    client
                );

                return res.status(400).json({
                    success: false,
                    error:
                        `La solicitud ya fue procesada como: ${withdrawal.status}`
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

            // Si se rechaza, devolver exactamente
            // los puntos retirados.
            if (
                status === 'rejected'
            ) {
                const pointsToRefund =
                    Math.round(
                        Number(
                            withdrawal.amount
                        ) /
                        POINT_TO_CURRENCY_RATIO
                    );

                const balanceUpdate =
                    await client.query(
                        `UPDATE web_users
                         SET points_balance =
                             points_balance + $1
                         WHERE id = $2
                         RETURNING id`,
                        [
                            pointsToRefund,
                            withdrawal.user_id
                        ]
                    );

                if (
                    balanceUpdate.rows.length === 0
                ) {
                    throw new Error(
                        'No se pudo devolver el saldo al usuario.'
                    );
                }

                await insertRewardEvent(
                    client,
                    {
                        userId:
                            withdrawal.user_id,

                        sourceType:
                            'WITHDRAWAL_REFUND',

                        transId:
                            `WITHDRAWAL_REFUND_${id}`,

                        points:
                            pointsToRefund
                    }
                );
            }

            await client.query(
                'COMMIT'
            );

            return res.json({
                success: true,

                message:
                    `Solicitud #${id} marcada como ${status}.`,

                withdrawal:
                    result.rows[0]
            });
        } catch (error) {
            await safeRollback(
                client
            );

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

app.use(
    (req, res) => {
        res.status(404).json({
            success: false,
            error:
                'Ruta no encontrada.'
        });
    }
);

// ============================================================
// MANEJO GLOBAL DE ERRORES
// ============================================================

app.use(
    (err, req, res, next) => {
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
    }
);

// ============================================================
// INICIALIZACIÓN
// ============================================================

async function startServer() {
    try {
        await db.query(
            'SELECT 1'
        );

        await ensureRewardTables();

        const server =
            app.listen(
                PORT,
                () => {
                    console.log(
                        `Servidor iniciado correctamente en puerto ${PORT}.`
                    );

                    console.log(
                        `CORS permitido: ${allowedOrigins.join(', ')}`
                    );
                }
            );

        server.on(
            'error',
            error => {
                console.error(
                    'Error iniciando servidor:',
                    error
                );

                process.exit(1);
            }
        );
    } catch (error) {
        console.error(
            'No se pudo inicializar el servidor:',
            error
        );

        await db.end()
            .catch(() => {});

        process.exit(1);
    }
}

process.on(
    'unhandledRejection',
    error => {
        console.error(
            'Unhandled Promise Rejection:',
            error
        );
    }
);

process.on(
    'uncaughtException',
    error => {
        console.error(
            'Uncaught Exception:',
            error
        );

        process.exit(1);
    }
);

startServer();
```
