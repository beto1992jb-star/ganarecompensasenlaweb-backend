const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5500;

// Configuración para procesar JSON y datos de formularios en peticiones POST
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos desde la carpeta actual
app.use(express.static(path.join(__dirname)));

// Ruta principal para entregar el index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Manejo de fallback para SPA o redirección al index
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`===========================================`);
    console.log(`🚀 Servidor Web activo en http://localhost:${PORT}`);
    console.log(`===========================================`);
});
