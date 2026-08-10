require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_change_me';

app.use(cors());
app.use(express.json());

// Configuración de la base de datos PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Middleware de Autenticación
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token no proporcionado.' });
    }

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ success: false, error: 'Token inválido o expirado.' });
    }
}

// Inicializador de Tablas PostgreSQL
async function ensureRewardTables() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Tabla de usuarios
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                referral_code VARCHAR(50) UNIQUE NOT NULL,
                referred_by INTEGER REFERENCES users(id),
                points_balance NUMERIC(12, 2) DEFAULT 0,
                country_code VARCHAR(10) DEFAULT 'AR',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Tabla de retiros
        await client.query(`
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                payout_method VARCHAR(50) NOT NULL,
                account_details TEXT NOT NULL,
                amount NUMERIC(10, 2) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Tabla de sesiones de anuncios
        await client.query(`
            CREATE TABLE IF NOT EXISTS ad_sessions (
                id VARCHAR(100) PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query('COMMIT');
        console.log("Tablas de base de datos verificadas/creadas con éxito.");
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error inicializando tablas:", err);
        throw err;
    } finally {
        client.release();
    }
}

/* --- RUTAS DE AUTENTICACIÓN Y PERFIL --- */

app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password, referral_code, country_code } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email y contraseña son requeridos.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userRefCode = Math.random().toString(36).substring(2, 8).toUpperCase();

        let referrerId = null;
        if (referral_code) {
            const refCheck = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referral_code.toUpperCase()]);
            if (refCheck.rows.length > 0) {
                referrerId = refCheck.rows[0].id;
            }
        }

        const newUser = await pool.query(
            `INSERT INTO users (email, password, referral_code, referred_by, country_code) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id, email, referral_code, points_balance`,
            [email.toLowerCase(), hashedPassword, userRefCode, referrerId, country_code || 'AR']
        );

        const user = newUser.rows[0];
        const token = jwt.encode({ id: user.id, email: user.email }, JWT_SECRET);

        res.json({ success: true, token, user });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ success: false, error: 'El correo electrónico ya está registrado.' });
        }
        res.status(500).json({ success: false, error: 'Error interno en el servidor.' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, error: 'Credenciales inválidas.' });
        }

        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(400).json({ success: false, error: 'Credenciales inválidas.' });
        }

        const token = jwt.encode({ id: user.id, email: user.email }, JWT_SECRET);
        delete user.password;

        res.json({ success: true, token, user });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Error en el inicio de sesión.' });
    }
});

app.get('/api/v1/user/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email, referral_code, points_balance FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }
        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Error al obtener datos del perfil.' });
    }
});

/* --- RUTAS DE ANUNCIOS MONETAG --- */

app.post('/api/v1/web-video/start', authenticateToken, async (req, res) => {
    try {
        const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
        await pool.query('INSERT INTO ad_sessions (id, user_id, status) VALUES ($1, $2, $3)', [sessionId, req.user.id, 'started']);
        
        // URL Direct Link de Monetag
        const directLinkUrl = process.env.MONETAG_DIRECT_LINK_URL || "https://example.com/ad-link";

        res.json({
            success: true,
            sessionId,
            adUrl: directLinkUrl,
            waitSeconds: 45
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Error al iniciar la sesión de anuncio.' });
    }
});

app.post('/api/v1/web-video/claim', authenticateToken, async (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId) {
        return res.status(400).json({ success: false, error: 'Falta el ID de sesión.' });
    }

    try {
        const sessionCheck = await pool.query('SELECT * FROM ad_sessions WHERE id = $1 AND user_id = $2', [sessionId, req.user.id]);
        if (sessionCheck.rows.length === 0) {
            return res.status(400).json({ success: false, error: 'Sesión de anuncio no válida.' });
        }

        if (sessionCheck.rows[0].status === 'claimed') {
            return res.status(400).json({ success: false, error: 'Esta recompensa ya fue acreditada.' });
        }

        const pointsToAward = 10;

        await pool.query('BEGIN');
        await pool.query('UPDATE ad_sessions SET status = $1 WHERE id = $2', ['claimed', sessionId]);
        await pool.query('UPDATE users SET points_balance = points_balance + $1 WHERE id = $2', [pointsToAward, req.user.id]);
        await pool.query('COMMIT');

        res.json({ success: true, pointsAwarded: pointsToAward });
    } catch (err) {
        await pool.query('ROLLBACK');
        res.status(500).json({ success: false, error: 'Error al acreditar los puntos.' });
    }
});

/* --- RUTAS DE ENCUESTAS Y RETIROS --- */

app.get('/api/v1/cpx/survey-url', authenticateToken, (req, res) => {
    const appId = process.env.CPX_APP_ID || '35135';
    const userId = req.user.id;
    const url = `https://offers.cpx-research.com/index.php?app_id=${appId}&ext_user_id=${userId}`;
    res.json({ success: true, url });
});

app.post('/api/v1/withdraw', authenticateToken, async (req, res) => {
    const { payout_method, account_details, amount } = req.body;

    if (!payout_method || !account_details || !amount) {
        return res.status(400).json({ success: false, error: 'Todos los campos son requeridos.' });
    }

    if (amount < 5.00) {
        return res.status(400).json({ success: false, error: 'El retiro mínimo es de $5.00 USD.' });
    }

    try {
        await pool.query(
            'INSERT INTO withdrawal_requests (user_id, payout_method, account_details, amount) VALUES ($1, $2, $3, $4)',
            [req.user.id, payout_method, account_details, amount]
        );
        res.json({ success: true, message: 'Solicitud de retiro registrada exitosamente.' });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Error al registrar la solicitud de retiro.' });
    }
});

// Inicialización del servidor HTTP y base de datos
ensureRewardTables()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Servidor activo en el puerto ${PORT}`);
        });
    })
    .catch(err => {
        console.error('Error de arranque en servidor:', err);
        process.exit(1);
    });
