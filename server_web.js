const express = require('express');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5500;

// 1. Configurar CORS para permitir peticiones locales y de producción
const allowedOrigins = [
  'https://ganarecompensasenlaweb.netlify.app',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir peticiones sin origen (como scripts locales/Postman) o dentro de la lista
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // En desarrollo puedes poner true para probar sin bloqueos
    }
  },
  credentials: true
}));

// 2. Middlewares para parsear JSON y formularios
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Servir archivos estáticos (CSS, JS, imágenes, terminos.html, juegos.html, etc.)
app.use(express.static(path.join(__dirname)));

// ==========================================
// 4. AQUÍ VAN TUS RUTAS Y ENDPOINTS DE LA API
// (Asegúrate de ponerlas ANTES del fallback app.get('*'))
// ==========================================

/* EJEMPLOS DE RUTAS QUE TU FRONTEND UTILIZA:

app.post('/api/v1/auth/login', (req, res) => { ... });
app.post('/api/v1/auth/register', (req, res) => { ... });
app.post('/api/v1/auth/forgot-password', (req, res) => { ... });
app.get('/api/v1/user/profile', (req, res) => { ... });
app.post('/api/v1/ad/start', (req, res) => { ... });
app.post('/api/v1/ad/claim', (req, res) => { ... });
app.get('/api/v1/cpx/survey-url', (req, res) => { ... });
app.post('/api/v1/withdraw/request', (req, res) => { ... });

*/

// 5. Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 6. Manejo de Fallback para SPA (Mover al FINAL del archivo)
app.get('*', (req, res) => {
    // Si la petición inicia con /api/, devolver JSON de error en lugar de index.html
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Endpoint API no encontrado' });
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 7. Iniciar el servidor
app.listen(PORT, () => {
    console.log(`===========================================`);
    console.log(`🚀 Servidor Web activo en http://localhost:${PORT}`);
    console.log(`===========================================`);
});
