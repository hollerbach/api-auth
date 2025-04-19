// src/interfaces/api/middlewares/validation.middleware.js
const { validationResult, param, query, body } = require('express-validator');
const { BadRequestError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');
const xss = require('xss');
const mongoSanitize = require('mongo-sanitize');

/**
 * Configurações para validações globais
 */
const validationConfig = {
  // Limites para diferentes tipos de dados
  limits: {
    // Limites gerais
    stringMaxLength: 1000,
    arrayMaxItems: 100,
    objectMaxProps: 50,
    
    // Limites para campos específicos
    email: {
      minLength: 3,
      maxLength: 254 // RFC 5321
    },
    name: {
      minLength: 1,
      maxLength: 100
    },
    password: {
      minLength: 8,
      maxLength: 128
    },
    comment: {
      maxLength: 2000
    },
    description: {
      maxLength: 5000
    },
    id: {
      length: 24 // MongoDB ObjectId padrão
    },
    token: {
      maxLength: 1024
    },
    url: {
      maxLength: 2048
    },
    phone: {
      maxLength: 20
    },
    // Limites para upload de arquivos são definidos no middleware de upload
  },
  
  // Caracteres permitidos para diferentes tipos de campos
  patterns: {
    alphaNumeric: /^[a-zA-Z0-9]+$/,
    alphaNumericWithSpaces: /^[a-zA-Z0-9 ]+$/,
    username: /^[a-zA-Z0-9_.\-@]+$/,
    name: /^[a-zA-Z0-9\s.\-']+$/,
    objectId: /^[0-9a-fA-F]{24}$/,
    uuid: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
    phone: /^\+?[0-9\s\-()]+$/,
    zip: /^[0-9\-]+$/,
    currencyCode: /^[A-Z]{3}$/,
    timezone: /^[a-zA-Z_/+-]+$/,
    locale: /^[a-z]{2}(-[A-Z]{2})?$/,
    twoFactorCode: /^\d{6}$/
  }
};

/**
 * Middleware para verificar resultados de validação
 * @param {Request} req Express Request
 * @param {Response} res Express Response
 * @param {NextFunction} next Express Next
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    // Formatar erros para um formato consistente e amigável
    const formattedErrors = errors.array().map(err => ({
      field: err.path,
      message: err.msg,
      value: err.value ? (
        // Remover ou mascarar valores sensíveis antes de incluir no log
        ['password', 'token', 'secret', 'credit_card', 'auth'].some(s => 
          err.path.toLowerCase().includes(s)
        ) ? '[REDACTED]' : typeof err.value === 'string' ? 
            err.value.length > 50 ? `${err.value.substring(0, 50)}...` : err.value 
            : JSON.stringify(err.value).length > 50 ? 'Object [too large]' : err.value
      ) : undefined
    }));
    
    // Registrar os erros de validação no log
    logger.warn(`Erro de validação: ${req.method} ${req.originalUrl}`, {
      ip: req.ip,
      errors: formattedErrors
    });
    
    // Lançar erro com lista formatada de erros
    throw new BadRequestError('Erro de validação nos dados fornecidos', formattedErrors);
  }
  
  next();
};

/**
 * Sanitiza dados para prevenir XSS
 * @param {any} data Dados a serem sanitizados
 * @returns {any} Dados sanitizados
 */
const sanitizeXss = (data) => {
  if (typeof data === 'string') {
    return xss(data, {
      whiteList: {}, // Não permitir nenhuma tag HTML
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script'] // Remover completamente scripts
    });
  } else if (Array.isArray(data)) {
    return data.map(sanitizeXss);
  } else if (data !== null && typeof data === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(data)) {
      result[key] = sanitizeXss(value);
    }
    return result;
  }
  return data;
};

/**
 * Middleware para sanitizar todos os dados de entrada
 * @returns {Function} Middleware para sanitização
 */
const sanitizeInputs = () => {
  return (req, res, next) => {
    // Sanitizar corpo da requisição
    if (req.body) {
      // Aplicar sanitização de XSS
      req.body = sanitizeXss(req.body);
      
      // Aplicar sanitização de MongoDB
      req.body = mongoSanitize(req.body);
    }
    
    // Sanitizar parâmetros da URL
    if (req.params) {
      req.params = sanitizeXss(req.params);
      req.params = mongoSanitize(req.params);
    }
    
    // Sanitizar query strings
    if (req.sanitizedQuery) {
      req.sanitizedQuery = sanitizeXss(req.sanitizedQuery);
      req.sanitizedQuery = mongoSanitize(req.sanitizedQuery);
    }
    
    next();
  };
};

/**
 * Middleware para validar e limitar o tamanho de requisições
 * @returns {Function} Middleware para limitar tamanho
 */
const limitPayloadSize = () => {
  return (req, res, next) => {
    // Verificar tamanho dos objetos nos dados
    const checkObjectDepthAndSize = (obj, path = '', depth = 1, maxDepth = 10) => {
      if (depth > maxDepth) {
        throw new BadRequestError(`Excedida profundidade máxima de objeto em ${path || 'payload'}`);
      }
      
      if (Array.isArray(obj)) {
        // Limitar tamanho de arrays
        if (obj.length > validationConfig.limits.arrayMaxItems) {
          throw new BadRequestError(`Array excede o limite máximo de ${validationConfig.limits.arrayMaxItems} itens em ${path || 'payload'}`);
        }
        
        // Verificar cada item do array
        obj.forEach((item, index) => {
          if (typeof item === 'object' && item !== null) {
            checkObjectDepthAndSize(item, `${path}[${index}]`, depth + 1, maxDepth);
          }
        });
      } else if (typeof obj === 'object' && obj !== null) {
        // Limitar número de propriedades
        const propCount = Object.keys(obj).length;
        if (propCount > validationConfig.limits.objectMaxProps) {
          throw new BadRequestError(`Objeto excede o limite máximo de ${validationConfig.limits.objectMaxProps} propriedades em ${path || 'payload'}`);
        }
        
        // Verificar cada propriedade
        for (const [key, value] of Object.entries(obj)) {
          const propPath = path ? `${path}.${key}` : key;
          
          // Verificar tamanho de strings
          if (typeof value === 'string' && value.length > validationConfig.limits.stringMaxLength) {
            throw new BadRequestError(`String excede o limite máximo de ${validationConfig.limits.stringMaxLength} caracteres em ${propPath}`);
          }
          
          // Verificar recursivamente objetos aninhados
          if (typeof value === 'object' && value !== null) {
            checkObjectDepthAndSize(value, propPath, depth + 1, maxDepth);
          }
        }
      }
    };
    
    // Verificar corpo da requisição se existir
    if (req.body && typeof req.body === 'object') {
      checkObjectDepthAndSize(req.body);
    }
    
    next();
  };
};

/**
 * Cria validators comuns para campos específicos
 * @returns {Object} Conjunto de validators reutilizáveis
 */
const validators = {
  // Validação de campos de identidade
  id: () => param('id')
    .isMongoId().withMessage('ID inválido')
    .customSanitizer(value => mongoSanitize(value)),
    
  uuid: () => param('uuid')
    .matches(validationConfig.patterns.uuid).withMessage('UUID inválido')
    .customSanitizer(value => mongoSanitize(value)),
  
  // Validação de campos de usuário
  email: () => body('email')
    .isEmail().withMessage('E-mail inválido')
    .normalizeEmail()
    .isLength({
      min: validationConfig.limits.email.minLength,
      max: validationConfig.limits.email.maxLength
    }).withMessage(`E-mail deve ter entre ${validationConfig.limits.email.minLength} e ${validationConfig.limits.email.maxLength} caracteres`),
    
  password: () => body('password')
    .isLength({
      min: validationConfig.limits.password.minLength,
      max: validationConfig.limits.password.maxLength
    }).withMessage(`Senha deve ter entre ${validationConfig.limits.password.minLength} e ${validationConfig.limits.password.maxLength} caracteres`)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial'),
    
  name: () => body('name')
    .optional()
    .isLength({
      min: validationConfig.limits.name.minLength,
      max: validationConfig.limits.name.maxLength
    }).withMessage(`Nome deve ter entre ${validationConfig.limits.name.minLength} e ${validationConfig.limits.name.maxLength} caracteres`)
    .matches(validationConfig.patterns.name).withMessage('Nome contém caracteres inválidos')
    .customSanitizer(value => xss(value)),
    
  role: () => body('role')
    .optional()
    .isIn(['user', 'admin']).withMessage('Função inválida'),
    
  // Validação de campos 2FA
  twoFactorToken: () => body('token')
    .isNumeric().withMessage('Token deve conter apenas números')
    .isLength({ min: 6, max: 6 }).withMessage('Token deve ter 6 dígitos'),
    
  recoveryCode: () => body('code')
    .isString().withMessage('Código de recuperação deve ser uma string')
    .isLength({ min: 8, max: 16 }).withMessage('Código de recuperação inválido')
    .customSanitizer(value => xss(value)),
    
  // Validação de campos de paginação
  page: () => query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Página deve ser um número positivo')
    .toInt(),
    
  limit: () => query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limite deve ser entre 1 e 100')
    .toInt(),
    
  // Validação para campos de busca
  search: () => query('search')
    .optional()
    .isString().withMessage('Termo de busca deve ser texto')
    .isLength({ max: 100 }).withMessage('Termo de busca muito longo')
    .customSanitizer(value => xss(value)),
  
  // Campo personalizado com validação e sanitização
  customField: (fieldName, options = {}) => {
    const field = body(fieldName);
    
    if (options.required !== false) {
      field.exists().withMessage(`${fieldName} é obrigatório`);
    } else {
      field.optional();
    }
    
    if (options.type) {
      switch (options.type) {
        case 'string':
          field.isString().withMessage(`${fieldName} deve ser texto`);
          break;
        case 'number':
          field.isNumeric().withMessage(`${fieldName} deve ser um número`);
          break;
        case 'boolean':
          field.isBoolean().withMessage(`${fieldName} deve ser um booleano`);
          break;
        case 'date':
          field.isISO8601().withMessage(`${fieldName} deve ser uma data válida`);
          break;
        case 'array':
          field.isArray({ max: options.maxItems || validationConfig.limits.arrayMaxItems })
            .withMessage(`${fieldName} deve ser um array com no máximo ${options.maxItems || validationConfig.limits.arrayMaxItems} itens`);
          break;
      }
    }
    
    if (options.minLength) {
      field.isLength({ min: options.minLength }).withMessage(`${fieldName} deve ter pelo menos ${options.minLength} caracteres`);
    }
    
    if (options.maxLength) {
      field.isLength({ max: options.maxLength }).withMessage(`${fieldName} deve ter no máximo ${options.maxLength} caracteres`);
    }
    
    if (options.pattern) {
      field.matches(options.pattern).withMessage(`${fieldName} possui formato inválido`);
    }
    
    if (options.customValidation) {
      field.custom(options.customValidation);
    }
    
    // Sempre sanitizar entrada
    field.customSanitizer(value => {
      let sanitized = value;
      
      // Sanitizar contra XSS
      if (typeof value === 'string') {
        sanitized = xss(sanitized);
      }
      
      // Sanitizar contra MongoDB injection
      sanitized = mongoSanitize(sanitized);
      
      return sanitized;
    });
    
    return field;
  }
};

/**
 * Factory para criar middlewares de validação específicos para cada schema
 * @param {Array} validationChain Cadeia de validadores
 * @returns {Array} Middlewares de validação
 */
const createValidator = (validationChain) => {
  return [sanitizeInputs(), limitPayloadSize(), ...validationChain, validate];
};

module.exports = {
  validate,
  sanitizeInputs,
  limitPayloadSize,
  validators,
  createValidator,
  validationConfig
};