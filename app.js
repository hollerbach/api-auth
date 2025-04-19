// src/app.js
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const xss = require('xss-clean');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const { csrfProtection, csrfErrorHandler } = require('./infrastructure/security/csrf.config');
const config = require('./infrastructure/config');
const setupRoutes = require('./interfaces/api/routes');
const errorMiddleware = require('./interfaces/api/middlewares/error.middleware');
const mongoSanitize = require('express-mongo-sanitize');

const path = require('path');

const app = express();

// Configurações de segurança
app.use(helmet());
app.use(cookieParser(config.security.cookieSecret));
app.use(xss());
app.use(mongoSanitize());

// Configuração de CORS
app.use(cors({
  origin: config.security.cors.allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token']
}));

// Middleware de compressão
app.use(compression());

// Logging em desenvolvimento
if (config.app.env === 'development') {
  app.use(morgan('dev'));
}

// Configurações do parser de corpo
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiter global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: config.security.rateLimit.max, // Limite por IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many requests, please try again later.'
  }
});
app.use('/api/', globalLimiter);

// Inicialização do passport
app.use(passport.initialize());
require('./infrastructure/security/passport.config')(passport);

// Aplicar proteção CSRF para todas as rotas, exceto as listadas em ignoredMethods
app.use(csrfProtection);
app.use(csrfErrorHandler);

// Rota para obter um token CSRF (usado pelo frontend)
app.get('/api/csrf-token', (req, res) => {
  const { generateToken } = require('./infrastructure/security/csrf.config');
  res.json({ csrfToken: generateToken(req, res) });
});

// Configurar rotas da API
console.log("Setting up routes...");
setupRoutes(app);
console.log("Routes setup complete");


// Middleware de tratamento de erros
app.use(errorMiddleware.errorHandler);

// Rota padrão para lidar com caminhos inexistentes
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

module.exports = app;