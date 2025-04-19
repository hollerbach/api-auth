// src/interfaces/api/controllers/health.controller.js
const healthMonitor = require('../../../infrastructure/monitoring/health-monitor');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Controlador para verificação de saúde da aplicação
 */
class HealthController {
  /**
   * Verifica o estado de saúde da aplicação e seus componentes
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async checkHealth(req, res) {
    try {
      // Verificar o nível de detalhe solicitado
      const detailed = req.sanitizedQuery.detailed === 'true';
      
      // Obter o status de saúde da aplicação
      const healthStatus = await healthMonitor.checkHealth();
      
      // Determinar o código de status HTTP com base no status geral
      const statusCode = healthStatus.status === 'UP' ? 200 : 503;
      
      // Filtrar dados sensíveis se não for detalhado
      if (!detailed) {
        // Remover detalhes do sistema
        delete healthStatus.system;
        
        // Simplificar informações dos serviços
        Object.keys(healthStatus.services || {}).forEach(service => {
          const serviceStatus = healthStatus.services[service];
          // Manter apenas o status, remover detalhes
          if (serviceStatus && typeof serviceStatus === 'object') {
            healthStatus.services[service] = {
              status: serviceStatus.status
            };
          }
        });
      }
      
      res.status(statusCode).json(healthStatus);
    } catch (error) {
      logger.error(`Erro ao verificar saúde: ${error.message}`);
      res.status(500).json({
        status: 'DOWN',
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
  }
  
  /**
   * Endpoint simples para verificar se a API está respondendo
   * Útil para load balancers e health checks básicos
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async ping(req, res) {
    res.status(200).json({
      status: 'UP',
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = new HealthController();