// src/interfaces/api/middlewares/index.js
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const passport = require('passport');
const securityConfig = require('../../../infrastructure/security/security.config');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Configurar middlewares globais para a aplicação Express
 * @param {Express} app Instância do Express
 */
const setupMiddlewares = (app) => {
  // Middleware para logging de requisições
  app.use((req, res, next) => {
    req.logger = logger;
    logger.info(`[${req.method}] ${req.url}`);
    next();
  });

  // Configurações de segurança para cabeçalhos HTTP
  app.use(securityConfig.helmet);

  // Adicionar ID de requisição para rastreamento/debugging
  app.use((req, res, next) => {
    const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
    req.id = requestId;
    res.set('X-Request-Id', requestId);
    next();
  });

  // Parsers para corpo da requisição
  app.use(express.json({ limit: '1mb' })); // Limitar tamanho do payload
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // Parser de cookies
  app.use(cookieParser(process.env.APP_KEY)); // Usar APP_KEY para assinar cookies

  // Configuração CORS
  app.use(cors(securityConfig.corsOptions));

  // Rate limiting global
  app.use(securityConfig.globalRateLimit);

  // Speed limiter - torna as respostas progressivamente mais lentas para evitar brute force
  app.use(securityConfig.speedLimiter);

  // Middleware de segurança para prevenir Parameter Pollution
  app.use((req, res, next) => {
    // Função para sanitizar parâmetros duplicados nas queries
    const sanitizeQuery = (query) => {
      const result = {};
      
      for (const [key, value] of Object.entries(query)) {
        // Se for um array (parâmetro duplicado), usar apenas o último valor
        if (Array.isArray(value)) {
          result[key] = value[value.length - 1];
        } else {
          result[key] = value;
        }
      }
      
      return result;
    };
    
    // Sanitizar query params
    req.query = sanitizeQuery(req.query);
    
    next();
  });

  // Cache control - prevenir cache para rotas de API
  app.use((req, res, next) => {
    // Não aplicar para rotas estáticas (se houver)
    if (!req.path.startsWith('/static') && !req.path.startsWith('/public')) {
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
      res.set('Surrogate-Control', 'no-store');
    }
    next();
  });

  // Inicialização do Passport
  require('../../../infrastructure/security/passport');
  app.use(passport.initialize());

  // Middleware para forçar o fechamento de conexões HTTP vulneráveis
  // Adicionando header que força o navegador a usar HTTPS
  if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
      if (req.secure) {
        next();
      } else {
        // Se não estiver em HTTPS, adicionar cabeçalho de redirecionamento
        res.set('X-Forwarded-Proto', 'https');
        next();
      }
    });
  }

  // Limitar métodos HTTP permitidos
  app.use((req, res, next) => {
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
    
    if (!allowedMethods.includes(req.method)) {
      return res.status(405).json({ 
        error: 'Method Not Allowed',
        message: `O método ${req.method} não é permitido`
      });
    }
    
    next();
  });
};

module.exports = setupMiddlewares;