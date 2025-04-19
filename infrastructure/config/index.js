// src/infrastructure/config/index.js
const logger = require('../logging/logger');

// Lista de variáveis de ambiente obrigatórias em produção
const requiredEnvVars = [
  'NODE_ENV',
  'PORT',
  'APP_KEY',
  'ALLOWED_ORIGINS',
  'BASE_URL',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
  'JWT_REFRESH_EXPIRES_IN',
  'EMAIL_HOST',
  'EMAIL_PORT',
  'EMAIL_USER',
  'EMAIL_PASS',
  'RECAPTCHA_SECRET',
  'APP_KEY',
  'DB_NAME',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET'
];

// Lista de variáveis de banco de dados que são opcionais em desenvolvimento
const dbEnvVars = [
  'DB_USER',
  'DB_PASS',
  'MONGODB_CLUSTER',
  'MONGODB_APP'
];

// Verificar variáveis obrigatórias
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    logger.error(`Variável de ambiente ${envVar} não definida`);
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`Variável de ambiente ${envVar} não definida`);
    }
  }
}

// Verificar variáveis de banco de dados
for (const envVar of dbEnvVars) {
  if (!process.env[envVar]) {
    if (process.env.NODE_ENV === 'production') {
      logger.warn(`Variável de ambiente ${envVar} não definida`);
      throw new Error(`Variável de ambiente ${envVar} não definida`);
    }
  }
}

// Add this to your config/index.js after loading environment variables
function validateURL(url, name) {
  try {
    new URL(url);
  } catch (e) {
    console.error(`Invalid URL format for ${name}: ${url}`);
    // Return a safe default or throw an error
  }
}

// Then use it
validateURL(process.env.BASE_URL, 'BASE_URL');


// Valores padrão para ambiente de desenvolvimento
const getMongoURI = () => {
  // Se estamos em desenvolvimento e faltam credenciais, usamos uma conexão local
  if (process.env.NODE_ENV !== 'production' ) {
    logger.info('Usando conexão MongoDB local para ambiente de desenvolvimento');
    return `mongodb://localhost:27017/${process.env.DB_NAME}`;
  }
  
  // Caso contrário, usamos a conexão Atlas com credenciais
  return `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@${process.env.MONGODB_CLUSTER}/${process.env.DB_NAME}?retryWrites=true&w=majority${process.env.MONGODB_APP ? `&appName=${process.env.MONGODB_APP}` : ''}`;
};

// Configurações organizadas por contexto
module.exports = {
  app: {
    env: process.env.NODE_ENV,
    port: process.env.PORT,
    appKey: process.env.APP_KEY,
    baseUrl: process.env.BASE_URL,
    frontendUrl: process.env.FRONTEND_URL
  },

  db: {
    uri: getMongoURI(),
    options: {
      // Opções de conexão podem ser definidas aqui se necessário
    }
  },

  auth: {
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN,
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN
    },
    recaptcha: {
      secret: process.env.RECAPTCHA_SECRET,
      scoreThreshold: 0.5
    },
    password: {
      saltRounds: 10,
      resetTokenExpiry: 15 * 60 * 1000 // 15 minutos
    },
    verification: {
      tokenExpiry: 30 * 60 * 1000 // 30 minutos
    }
  },

  // Adicionar configurações OAuth
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl: `${process.env.BASE_URL}/auth/google/callback`,
      redirectUrl: process.env.FRONTEND_URL || process.env.BASE_URL
    }
  },

  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10),
    secure: parseInt(process.env.EMAIL_PORT, 10) === 465,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    from: `"Mercearia Digital" <${process.env.EMAIL_USER}>`
  },

  security: {
    cors: {
      allowedOrigins: (process.env.ALLOWED_ORIGINS).split(','),
      credentials: true
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: 100, // limite por IP
      loginMax: 10 // limite específico para login
    },
    csrf: {
      cookie: {
        key: 'csrf-token',
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
      }
    }
  }
};