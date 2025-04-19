// src/server.js
const path = require('path');
const cluster = require('cluster');
const os = require('os');

// Definir o arquivo de ambiente com base no NODE_ENV
const envFile = process.env.NODE_ENV === 'production' ? '.env' : '.env.local';

// Carregar as variáveis do arquivo apropriado
require('dotenv').config({
  path: path.resolve(process.cwd(), envFile)
});

// Importações principais
const app = require('./app');
const { connectToDatabase } = require('./infrastructure/database/mongodb/connection');
const logger = require('./infrastructure/logging/logger');
const config = require('./infrastructure/config');
const gracefulShutdown = require('./infrastructure/utils/graceful-shutdown');

// Tratamento global de exceções não tratadas
process.on('uncaughtException', err => {
  logger.error('UNCAUGHT EXCEPTION! Encerrando...');
  logger.error(err.name, err.message, err.stack);
  process.exit(1);
});

// Tratamento global de rejeições de promises não tratadas
process.on('unhandledRejection', (reason, promise) => {
  logger.error('UNHANDLED REJECTION! Potencial memory leak');
  logger.error(reason);
  // Não encerramos o processo, mas registramos para investigação
});

// Definir número de workers para cluster
const numCPUs = os.cpus().length;
const enableCluster = process.env.ENABLE_CLUSTER === 'true' && process.env.NODE_ENV === 'production';
const workerCount = process.env.WORKER_COUNT ? parseInt(process.env.WORKER_COUNT, 10) : numCPUs;

/**
 * Iniciar a aplicação
 */
const startServer = async () => {
  try {
    // Conectar ao banco de dados
    await connectToDatabase();
    logger.info(`✅ Conectado ao MongoDB`);

    // Iniciar servidor HTTP
    const server = app.listen(config.app.port, () => {
      logger.info(`🚀 Server rodando na porta ${config.app.port} em modo ${config.app.env}`);
      logger.info(`🌐 Usando arquivo de configuração: ${envFile}`);
      
      // Em desenvolvimento, exibir URL de documentação
      if (config.app.env === 'development') {
        logger.info(`📚 Documentação disponível em: http://localhost:${config.app.port}/docs`);
      }
    });
   
    // Configurar gerenciamento de desligamento gracioso
    gracefulShutdown.registerServer(server);

    // Adicionar middleware para rastrear requisições (usado no desligamento gracioso)
    app.use((req, res, next) => {
      if (gracefulShutdown.trackRequest(req, res)) {
        next();
      }
      // Se retornar false, a resposta já foi enviada
    });

    return server;
  } catch (error) {
    logger.error(`❌ Erro ao iniciar a aplicação: ${error.message}`);
    logger.error(`Stack trace: ${error.stack}`);
    process.exit(1);
  }
};

// Lógica para execução em cluster ou standalone
if (enableCluster && cluster.isMaster) {
  logger.info(`🧠 Modo Cluster ativado. Iniciando ${workerCount} workers...`);

  // Iniciar workers
  for (let i = 0; i < workerCount; i++) {
    cluster.fork();
  }

  // Lidar com término de worker
  cluster.on('exit', (worker, code, signal) => {
    const exitReason = signal ? `sinal ${signal}` : `código ${code}`;
    logger.warn(`Worker ${worker.process.pid} morreu (${exitReason})`);
    
    // Iniciar novo worker para substituir o que morreu
    if (code !== 0 && !worker.exitedAfterDisconnect) {
      logger.info('Iniciando novo worker para substituição...');
      cluster.fork();
    }
  });

  // Gerenciar desligamento gracioso para o cluster
  ['SIGINT', 'SIGTERM'].forEach(signal => {
    process.on(signal, () => {
      logger.info(`Recebido ${signal}, encerrando workers...`);
  
      // Iterar sobre workers e enviar sinal para desligamento
      Object.values(cluster.workers).forEach(worker => {
        worker.send('shutdown');
      });
  
      // Aguardar até 30 segundos para workers encerrarem
      const forceKillTimeout = setTimeout(() => {
        logger.error('Tempo limite excedido. Forçando encerramento dos workers.');
        Object.values(cluster.workers).forEach(worker => {
          if (!worker.isDead()) {
            worker.process.kill();
          }
        });
        process.exit(1);
      }, 30000);
  
      // Verificar periodicamente se todos os workers foram encerrados
      const checkWorkersInterval = setInterval(() => {
        const workerCount = Object.keys(cluster.workers).length;
        if (workerCount === 0) {
          clearInterval(checkWorkersInterval);
          clearTimeout(forceKillTimeout);
          logger.info('Todos os workers encerrados com sucesso.');
          process.exit(0);
        }
      }, 1000);
    });
  });
} else {
  // Worker ou modo standalone
  startServer().then(server => {
    if (enableCluster) {
      // Configuração específica para workers
      logger.info(`Worker ${process.pid} iniciado`);
      
      // Escutar mensagens do master
      process.on('message', message => {
        if (message === 'shutdown') {
          gracefulShutdown.shutdown('WORKER_SHUTDOWN');
        }
      });
    }
  });
}