// src/infrastructure/security/security.config.js
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const config = require('../config');

/**
 * Configurações de segurança para a aplicação
 */
const securityConfig = {
  /**
   * Configuração do Helmet para cabeçalhos de segurança
   * Implementa todas as proteções recomendadas pelo OWASP
   */
  helmet: helmet({
    // Content Security Policy (CSP) restritivo
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],  // Negar tudo por padrão (postura mais restritiva)
        scriptSrc: [
          "'self'",
          // Restringir apenas aos domínios necessários para reCaptcha
          'https://www.google.com/recaptcha/',
          'https://www.gstatic.com/recaptcha/'
        ],
        connectSrc: ["'self'"],  // Permitir apenas conexões para a própria origem
        imgSrc: ["'self'", 'data:'],  // Imagens da própria origem e data URIs
        styleSrc: [
          "'self'",
          // Permitir apenas estilos inline estritamente necessários
          'https://fonts.googleapis.com'
        ],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        formAction: ["'self'"],  // Formulários só podem submeter para a própria origem
        frameSrc: [
          "'self'",
          'https://www.google.com/recaptcha/'
        ],
        objectSrc: ["'none'"],  // Bloquear <object>, <embed> e <applet>
        baseUri: ["'self'"],  // Restringir <base> para própria origem
        frameAncestors: ["'none'"],  // Ninguém pode usar sua aplicação em frames
        upgradeInsecureRequests: config.app.env === 'production' ? [] : null, // Forçar HTTPS em produção
        blockAllMixedContent: config.app.env === 'production' ? [] : null, // Bloquear conteúdo misto em produção
      }
    },
    
    // Cross-Origin Opener Policy
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    
    // Cross-Origin Embedder Policy
    // Desativado para permitir recursos de terceiros como reCAPTCHA
    crossOriginEmbedderPolicy: false,
    
    // Cross-Origin Resource Policy
    crossOriginResourcePolicy: { policy: 'same-origin' },
    
    // Referrer Policy
    referrerPolicy: { 
      policy: 'strict-origin-when-cross-origin'
    },
    
    // HTTP Strict Transport Security
    // Forçar HTTPS por 1 ano
    hsts: {
      maxAge: 31536000, // 1 ano em segundos
      includeSubDomains: true,
      preload: true
    },
    
    // Prevenir sniffing de MIME type
    noSniff: true,
    
    // Proteção XSS
    xssFilter: true,
    
    // Prevenir que a aplicação seja carregada em iframes
    frameguard: {
      action: 'deny'
    },
    
    // Configurações para originAgentCluster
    originAgentCluster: true,
    
    // DNS Prefetch Control
    dnsPrefetchControl: { allow: false },
    
    // Permissions Policy (antes Feature-Policy)
    // Restringir acesso a APIs sensíveis do navegador
    permissionsPolicy: {
      features: {
        camera: ["'none'"],
        microphone: ["'none'"],
        geolocation: ["'none'"],
        payment: ["'none'"],
        usb: ["'none'"],
        fullscreen: ["'self'"],
        accelerometer: ["'none'"],
        ambientLightSensor: ["'none'"],
        autoplay: ["'none'"],
        battery: ["'none'"],
        displayCapture: ["'none'"],
        document: ["'self'"],
        documentDomain: ["'none'"],
        encryptedMedia: ["'none'"],
        executionWhileNotRendered: ["'none'"],
        executionWhileOutOfViewport: ["'none'"],
        gyroscope: ["'none'"],
        hid: ["'none'"],
        idleDetection: ["'none'"],
        magnetometer: ["'none'"],
        midi: ["'none'"],
        navigationOverride: ["'none'"],
        pictureInPicture: ["'none'"],
        serial: ["'none'"],
        speakerSelection: ["'none'"],
        syncXhr: ["'none'"],
        unoptimizedImages: ["'none'"],
        unsizedMedia: ["'none'"],
        vibrate: ["'none'"],
        vr: ["'none'"],
        wakeLock: ["'none'"],
        xr: ["'none'"]
      }
    }
  }),

  /**
   * Configurações para cookies
   * Define padrões seguros para todos os cookies da aplicação
   */
  cookieOptions: {
    // Opções padrão para cookies não sensíveis
    standard: {
      httpOnly: true, // Não acessível via JavaScript
      secure: config.app.env === 'production', // HTTPS apenas em produção
      sameSite: 'lax' // Protege contra CSRF, mas permite navegação normal
    },
    
    // Opções para cookies sensíveis (autenticação, sessão)
    sensitive: {
      httpOnly: true,
      secure: config.app.env === 'production',
      sameSite: 'strict', // Maior proteção contra CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dias (ou ajustar conforme necessário)
      path: '/',
      domain: undefined // Define com base no domínio atual
    },
    
    // Opções específicas para token de refresh
    refreshToken: {
      httpOnly: true,
      secure: config.app.env === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 dias
      path: '/api/auth', // Restrito apenas para rotas de autenticação
      domain: undefined
    }
  },

  /**
   * Rate limiter global para todas as requisições
   */
  globalRateLimit: rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Muitas requisições deste IP, tente novamente mais tarde',
    skipSuccessfulRequests: false
  }),

  /**
   * Rate limiter específico para autenticação
   */
  authRateLimit: rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.loginMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Muitas tentativas de autenticação. Tente novamente mais tarde.',
    skipSuccessfulRequests: false
  }),

  /**
   * Limitador para rotas sensíveis (redefinição de senha, etc)
   */
  sensitiveRateLimit: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 5, // 5 solicitações por hora
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Limite excedido para operações sensíveis. Tente novamente mais tarde.',
    skipSuccessfulRequests: false
  }),

  /**
   * Speed limiter - Torna as respostas progressivamente mais lentas
   * Útil para prevenir brute force mesmo respeitando rate limits
   */
  speedLimiter: slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutos
    delayAfter: 30, // permitir 30 requisições normais
    delayMs: (hits) => hits * 100, // adiciona 100ms para cada requisição após o limite
    maxDelayMs: 10000 // máximo de 10 segundos de delay
  }),

  /**
   * Cross-Origin Resource Sharing options
   * Configuração restritiva para CORS
   */
  corsOptions: {
    origin: (origin, callback) => {
      const allowedOrigins = config.security.cors.allowedOrigins;
      
      // Se não tiver origem (requisições do mesmo site) ou a origem for permitida
      if (!origin || allowedOrigins.includes(origin) || 
          (config.app.env === 'development' && allowedOrigins.includes('*'))) {
        callback(null, true);
      } else {
        callback(new Error('Não permitido por CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Length', 'X-Request-Id'],
    credentials: config.security.cors.credentials,
    maxAge: 86400, // Cache preflight por 24 horas
    preflightContinue: false,
    optionsSuccessStatus: 204
  }
};

module.exports = securityConfig;