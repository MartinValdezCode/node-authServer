const express = require('express');
const cors = require('cors');
const { dbConnection } = require('./db/config');
require('dotenv').config({
    path: './src/.env'
});

// Crear el servidor/aplicación de express
const app = express();

// Base de datos
dbConnection();

// Directorio Público
app.use(express.static('./src/public'));

// CORS
app.use(cors());

// Lectura y parseo del body
app.use(express.json());

// Rutas
app.use('/api/auth', require('./routes/auth'));

// Inicia servidor en puerto especificado
app.listen(process.env.PORT, () => {
    console.log(`Servidor corriendo en puerto ${process.env.PORT}`);
});

