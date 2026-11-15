# 🌐 GanaRecompensasEnLaWeb — Frontend (Interfaz de Usuario)

Interfaz web moderna y responsiva desarrollada en **HTML5, CSS3 y JavaScript Vanilla** para la plataforma de recompensas (GPT - *Get Paid To*), minijuegos interactivos, integración de Offerwalls y gestión de saldo de usuarios.

## ✨ Características Principales

* **Diseño UI/UX Moderno (Glassmorphism)**: Interfaz adaptada con efectos de desenfoque, gradientes dinámicos, tarjetas interactivas con seguimiento de cursor y notificaciones flotantes (*Toast Notifications*).
* **Autenticación Completa**: Vistas dinámicas para Iniciar Sesión, Registro con código de invitación por URL (`?ref=...`) y recuperación de contraseña asistida.
* **Módulos de Gamificación y Retención**:
  * 🎯 **Misión Diaria de Anuncios**: Control visual de progreso (hasta 24 anuncios diarios con sincronización horaria de Argentina).
  * 🎲 **Ruleta Diaria de la Suerte**: Ruleta interactiva animada con Canvas para sumar puntos extra diarios.
  * 🔥 **Racha de Conexión (7 Días)**: Sistema de recompensas progresivas por inicio de sesión consecutivo.
  * 🕹️ **Arena Arcade**: Minijuego de memoria progresivo (parejas de emojis) con sincronización de niveles.
  * ⚡ **Desafío de Reacción Rápida**: Prueba cronometrada de reflejos en milisegundos.
  * 🎯 **Reto de Atención y Memoria**: Entrenamiento de secuencias lumínicas y auditivas.
* **Rankings Globales (Top 10)**: Visualización en tiempo real de las tres tablas de líderes de la temporada (Arcade, Reacción y Atención) con enmascaramiento de privacidad en correos electrónicos.
* **Monetización e Integraciones**:
  * Acceso directo a los muros de ofertas de **AyeT-Studios** y encuestas de **CPX Research**.
  * Controladores automáticos en segundo plano para anuncios y recarga dinámica de saldo.
* **Panel de Retiros**: Formulario validado para solicitar pagos a Mercado Pago (CVU/Alias) y PayPal con montos mínimos.

## 🛠️ Stack Tecnológico

* **Estructura y Estilos**: HTML5, CSS3 (Variables CSS, Grid, Flexbox, Animaciones Keyframes)
* **Lógica**: JavaScript Vanilla (ES6+, Fetch API, Async/Await, LocalStorage)
* **Gráficos y Animaciones**: HTML5 Canvas API
* **PWA Ready**: Soporte para Service Workers (`sw.js`)

## 📂 Estructura del Archivo Principal

* `index.html`: Aplicación de página única (SPA) que administra dinámicamente las secciones de autenticación, el panel principal (Dashboard), los minijuegos, los rankings y los formularios de retiro conectándose directamente a la API RESTful en Node.js/Express.

## 🔌 Conexión con la API

La interfaz está configurada para comunicarse de manera segura mediante tokens **JWT** almacenados en el navegador con la API backend alojada en Render:
* **Base URL de la API**: `https://ganarecompensasenlaweb-backend1.onrender.com`

## 🚀 Despliegue

Optimizado para despliegues rápidos y gratuitos en plataformas estáticas como **Netlify** o **GitHub Pages**.
