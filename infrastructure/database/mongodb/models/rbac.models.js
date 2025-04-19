// src/infrastructure/database/mongodb/models/rbac.models.js
const mongoose = require('mongoose');

/**
 * Modelo para permissões
 * Define operações específicas que podem ser realizadas
 */
const PermissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  code: {
    type: String,
    required: true,
    trim: true,
    uppercase: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    enum: ['user', 'product', 'order', 'delivery', 'report', 'system'],
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

PermissionSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

/**
 * Modelo para recursos da aplicação
 * Representam entidades ou funcionalidades protegidas
 */
const ResourceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['route', 'entity', 'feature', 'report', 'menu'],
    required: true
  },
  path: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

ResourceSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

/**
 * Modelo para papéis (roles)
 * Representam funções ou cargos que agrupam permissões
 */
const RoleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  isSystem: {
    type: Boolean,
    default: false
  },
  permissions: [{
    permission: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Permission',
      required: true
    },
    resources: [{
      resource: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Resource'
      },
      conditions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    }]
  }],
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

RoleSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Índices para melhorar performance
PermissionSchema.index({ code: 1 });
PermissionSchema.index({ category: 1 });
ResourceSchema.index({ type: 1 });
ResourceSchema.index({ path: 1 });
RoleSchema.index({ isSystem: 1 });

// Criar modelos
const Permission = mongoose.model('Permission', PermissionSchema);
const Resource = mongoose.model('Resource', ResourceSchema);
const Role = mongoose.model('Role', RoleSchema);

module.exports = {
  Permission,
  Resource,
  Role
};