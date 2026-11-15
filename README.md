# 🚀 GanaRecompensasEnLaWeb — Backend API

API RESTful desarrollada en **Node.js** y **Express** con base de datos **PostgreSQL**, diseñada para gestionar el ecosistema completo de la plataforma de recompensas (GPT), minijuegos interactivos, sincronización de niveles y postbacks de offerwalls.

## ✨ Características Principales

* **Autenticación Segura**: Registro de usuarios, encriptación con `bcryptjs`, autenticación por tokens **JWT** y flujo de recuperación de contraseña.
* **Gamificación y Transacciones**:
  * Sincronización de niveles progresivos para minijuegos (**Arcade**, **Reacción Rápida** y **Atención y Memoria**).
  * Lógica transaccional de puntos en PostgreSQL con reseteo semanal automático y premios al Top 3.
* **Integración S2S Postbacks**: Endpoints seguros para procesar recompensas automáticas desde offerwalls de **CPX Research** y **AyeT-Studios**.
* **Gestión de Retiros**: Solicitudes de pago validadas con mínimo de $5.00 USD y panel administrativo completo para aprobar o rechazar transacciones.

## 🛠️ Stack Tecnológico

* **Runtime**: Node.js (ES Modules)
* **Framework**: Express.js
* **Base de Datos**: PostgreSQL (`pg` Pool)
* **Seguridad**: JSON Web Tokens, `bcryptjs`, `cors`

## 📂 Archivos del Repositorio

* `server_web.js`: Servidor principal, conexión a base de datos, rutas de la API, autenticación y lógica de negocio.
* `package.json`: Dependencias del proyecto y scripts de ejecución.

## 🚀 Despliegue

Configurado para ejecutarse en entornos cloud como **Render**.
