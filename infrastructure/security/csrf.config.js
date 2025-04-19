// src/infrastructure/security/csrf.config.js
const { doubleCsrf } = require('csrf-csrf');
const config = require('../config');

// Configurações do CSRF
const csrfConfig = {
  getSecret: () => config.security.csrfSecret || 'default-csrf-secret-key',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax', // Deve ser 'lax' para OAuth
    secure: config.app.env === 'production',
    signed: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 dia
  },
  size: 64, // tamanho do token em bytes
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getTokenFromRequest: (req) => req.headers['x-csrf-token']
};

// Inicializar o middleware CSRF
const { generateToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf(csrfConfig);

// Middleware para lidar com erros CSRF
const csrfErrorHandler = (err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ 
      error: 'CSRF validation failed',
      message: 'Invalid or missing CSRF token'
    });
  }
  next(err);
};

module.exports = {
  generateToken,
  csrfProtection: doubleCsrfProtection,
  csrfErrorHandler
};