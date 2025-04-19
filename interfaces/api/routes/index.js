// src/interfaces/api/routes/index.js
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
const healthController = require('../controllers/health.controller');

// Importar rotas de domínios
const authRoutes = require('./auth.routes');
const userRoutes = require('./user.routes');
const rbacRoutes = require('./rbac.routes');
// Futuros domínios
// const productRoutes = require('./product.routes');
// const orderRoutes = require('./order.routes');

/**
 * Configura todas as rotas da API
 * @param {Express} app Instância do Express
 */
const setupRoutes = (app) => {
  // Carregar documentação Swagger
  try {
    const swaggerDocument = YAML.load(path.join(process.cwd(), 'docs/swagger.yaml'));
    app.use(
      '/docs',
      swaggerUi.serve,
      swaggerUi.setup(swaggerDocument, {
        customCss: '.swagger-ui .topbar { display: none }'
      })
    );
  } catch (error) {
    console.error('Erro ao carregar documentação Swagger:', error.message);
  }

  // Rota de verificação de saúde
  app.get('/health', healthController.checkHealth);

  // API v1 routes
  const apiPrefix = '/api';

  // Montar as rotas de autenticação
  app.use(`${apiPrefix}/auth`, authRoutes);
  
  // Montar as rotas de usuários
  app.use(`${apiPrefix}/users`, userRoutes);
  
  // Montar as rotas de RBAC
  app.use(`${apiPrefix}/rbac`, rbacRoutes);

  // Preparado para futuros domínios
  // app.use(`${apiPrefix}/products`, productRoutes);
  // app.use(`${apiPrefix}/orders`, orderRoutes);
};

module.exports = setupRoutes;