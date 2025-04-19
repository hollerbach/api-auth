// scripts/seed-rbac.js
require('dotenv').config();
const mongoose = require('mongoose');
const { Role, Permission, Resource } = require('../infrastructure/database/mongodb/models/rbac.models');
const User = require('../infrastructure/database/mongodb/models/user.model');
const bcrypt = require('bcryptjs');
const config = require('../infrastructure/config');

// Dados básicos de permissões para o sistema
const permissions = [
  // Permissões de Usuário
  {
    name: 'Visualizar Usuários',
    code: 'USER_VIEW',
    description: 'Permissão para visualizar usuários',
    category: 'user'
  },
  {
    name: 'Criar Usuários',
    code: 'USER_CREATE',
    description: 'Permissão para criar novos usuários',
    category: 'user'
  },
  {
    name: 'Editar Usuários',
    code: 'USER_EDIT',
    description: 'Permissão para editar usuários existentes',
    category: 'user'
  },
  {
    name: 'Desativar Usuários',
    code: 'USER_DELETE',
    description: 'Permissão para desativar usuários',
    category: 'user'
  },
  
  // Permissões de Papéis
  {
    name: 'Visualizar Papéis',
    code: 'ROLE_VIEW',
    description: 'Permissão para visualizar papéis',
    category: 'system'
  },
  {
    name: 'Criar Papéis',
    code: 'ROLE_CREATE',
    description: 'Permissão para criar novos papéis',
    category: 'system'
  },
  {
    name: 'Editar Papéis',
    code: 'ROLE_EDIT',
    description: 'Permissão para editar papéis existentes',
    category: 'system'
  },
  {
    name: 'Excluir Papéis',
    code: 'ROLE_DELETE',
    description: 'Permissão para excluir papéis',
    category: 'system'
  },
  
  // Permissões de Permissões
  {
    name: 'Visualizar Permissões',
    code: 'PERMISSION_VIEW',
    description: 'Permissão para visualizar permissões',
    category: 'system'
  },
  {
    name: 'Criar Permissões',
    code: 'PERMISSION_CREATE',
    description: 'Permissão para criar novas permissões',
    category: 'system'
  },
  {
    name: 'Editar Permissões',
    code: 'PERMISSION_EDIT',
    description: 'Permissão para editar permissões existentes',
    category: 'system'
  },
  {
    name: 'Excluir Permissões',
    code: 'PERMISSION_DELETE',
    description: 'Permissão para excluir permissões',
    category: 'system'
  },
  
  // Permissões de Relação Papel-Permissão
  {
    name: 'Atribuir Permissão a Papel',
    code: 'ROLE_PERMISSION_ASSIGN',
    description: 'Permissão para atribuir permissões a papéis',
    category: 'system'
  },
  {
    name: 'Remover Permissão de Papel',
    code: 'ROLE_PERMISSION_REMOVE',
    description: 'Permissão para remover permissões de papéis',
    category: 'system'
  },
  
  // Permissões de Relação Usuário-Papel
  {
    name: 'Atribuir Papel a Usuário',
    code: 'USER_ROLE_ASSIGN',
    description: 'Permissão para atribuir papéis a usuários',
    category: 'user'
  },
  {
    name: 'Remover Papel de Usuário',
    code: 'USER_ROLE_REMOVE',
    description: 'Permissão para remover papéis de usuários',
    category: 'user'
  },
  {
    name: 'Visualizar Papéis de Usuário',
    code: 'USER_ROLE_VIEW',
    description: 'Permissão para visualizar papéis de usuários',
    category: 'user'
  },
  
  // Permissões de Produto
  {
    name: 'Visualizar Produtos',
    code: 'PRODUCT_VIEW',
    description: 'Permissão para visualizar produtos',
    category: 'product'
  },
  {
    name: 'Criar Produtos',
    code: 'PRODUCT_CREATE',
    description: 'Permissão para criar novos produtos',
    category: 'product'
  },
  {
    name: 'Editar Produtos',
    code: 'PRODUCT_EDIT',
    description: 'Permissão para editar produtos existentes',
    category: 'product'
  },
  {
    name: 'Excluir Produtos',
    code: 'PRODUCT_DELETE',
    description: 'Permissão para excluir produtos',
    category: 'product'
  },
  
  // Permissões de Pedido
  {
    name: 'Visualizar Pedidos',
    code: 'ORDER_VIEW',
    description: 'Permissão para visualizar pedidos',
    category: 'order'
  },
  {
    name: 'Criar Pedidos',
    code: 'ORDER_CREATE',
    description: 'Permissão para criar novos pedidos',
    category: 'order'
  },
  {
    name: 'Processar Pedidos',
    code: 'ORDER_PROCESS',
    description: 'Permissão para processar pedidos',
    category: 'order'
  },
  {
    name: 'Cancelar Pedidos',
    code: 'ORDER_CANCEL',
    description: 'Permissão para cancelar pedidos',
    category: 'order'
  },
  
  // Permissões de Entrega
  {
    name: 'Visualizar Entregas',
    code: 'DELIVERY_VIEW',
    description: 'Permissão para visualizar entregas',
    category: 'delivery'
  },
  {
    name: 'Gerenciar Entregas',
    code: 'DELIVERY_MANAGE',
    description: 'Permissão para gerenciar entregas',
    category: 'delivery'
  },
  
  // Permissões de Relatório
  {
    name: 'Visualizar Relatórios',
    code: 'REPORT_VIEW',
    description: 'Permissão para visualizar relatórios',
    category: 'report'
  },
  {
    name: 'Exportar Relatórios',
    code: 'REPORT_EXPORT',
    description: 'Permissão para exportar relatórios',
    category: 'report'
  }
];

// Recursos básicos do sistema
const resources = [
  // Recursos de API - Usuários
  {
    name: 'API Usuários - Listar',
    description: 'Endpoint para listar usuários',
    type: 'route',
    path: '/api/users'
  },
  {
    name: 'API Usuários - Detalhes',
    description: 'Endpoint para obter detalhes de um usuário',
    type: 'route',
    path: '/api/users/:id'
  },
  {
    name: 'API Usuários - Criar',
    description: 'Endpoint para criar usuários',
    type: 'route',
    path: '/api/users/create'
  },
  {
    name: 'API Usuários - Atualizar',
    description: 'Endpoint para atualizar usuários',
    type: 'route',
    path: '/api/users/:id/update'
  },
  
  // Recursos de API - RBAC
  {
    name: 'API RBAC - Papéis',
    description: 'Endpoints para gerenciar papéis',
    type: 'route',
    path: '/api/rbac/roles'
  },
  {
    name: 'API RBAC - Permissões',
    description: 'Endpoints para gerenciar permissões',
    type: 'route',
    path: '/api/rbac/permissions'
  },
  
  // Recursos de API - Produtos
  {
    name: 'API Produtos - Listar',
    description: 'Endpoint para listar produtos',
    type: 'route',
    path: '/api/products'
  },
  {
    name: 'API Produtos - Detalhes',
    description: 'Endpoint para obter detalhes de um produto',
    type: 'route',
    path: '/api/products/:id'
  },
  {
    name: 'API Produtos - Criar',
    description: 'Endpoint para criar produtos',
    type: 'route',
    path: '/api/products/create'
  },
  {
    name: 'API Produtos - Atualizar',
    description: 'Endpoint para atualizar produtos',
    type: 'route',
    path: '/api/products/:id/update'
  },
  
  // Recursos de API - Pedidos
  {
    name: 'API Pedidos - Listar',
    description: 'Endpoint para listar pedidos',
    type: 'route',
    path: '/api/orders'
  },
  {
    name: 'API Pedidos - Detalhes',
    description: 'Endpoint para obter detalhes de um pedido',
    type: 'route',
    path: '/api/orders/:id'
  },
  {
    name: 'API Pedidos - Criar',
    description: 'Endpoint para criar pedidos',
    type: 'route',
    path: '/api/orders/create'
  },
  {
    name: 'API Pedidos - Atualizar Status',
    description: 'Endpoint para atualizar status de pedidos',
    type: 'route',
    path: '/api/orders/:id/status'
  },
  
  // Recursos de Menu
  {
    name: 'Menu Administrativo',
    description: 'Menu de administração do sistema',
    type: 'menu',
    path: 'admin'
  },
  {
    name: 'Menu Usuários',
    description: 'Menu de gestão de usuários',
    type: 'menu',
    path: 'admin/users'
  },
  {
    name: 'Menu Produtos',
    description: 'Menu de gestão de produtos',
    type: 'menu',
    path: 'admin/products'
  },
  {
    name: 'Menu Pedidos',
    description: 'Menu de gestão de pedidos',
    type: 'menu',
    path: 'admin/orders'
  },
  {
    name: 'Menu Relatórios',
    description: 'Menu de relatórios',
    type: 'menu',
    path: 'admin/reports'
  }
];

// Papéis básicos do sistema
const roles = [
  {
    name: 'admin',
    description: 'Administrador do sistema com acesso total',
    isSystem: true
  },
  {
    name: 'gerente',
    description: 'Gerente com acesso para gerenciar a operação da loja',
    isSystem: true
  },
  {
    name: 'vendedor',
    description: 'Vendedor com acesso para criar e gerenciar pedidos',
    isSystem: true
  },
  {
    name: 'estoquista',
    description: 'Estoquista com acesso para gerenciar produtos e estoque',
    isSystem: true
  },
  {
    name: 'cliente',
    description: 'Cliente com acesso básico à loja',
    isSystem: true
  }
];

// Função principal para seed de dados
const seedRbacData = async () => {
  try {
    // Conectar ao banco de dados
    await mongoose.connect(config.db.uri);
    console.log('Conectado ao MongoDB');

    // Limpar dados existentes (opcional - cuidado em produção)
    console.log('Limpando dados existentes...');
    await Permission.deleteMany({});
    await Resource.deleteMany({});
    await Role.deleteMany({});
    
    // Não excluímos usuários para preservar dados existentes
    // Apenas atualizaremos a estrutura de papéis

    // 1. Criar permissões
    console.log('Criando permissões...');
    const createdPermissions = await Permission.insertMany(permissions);
    console.log(`${createdPermissions.length} permissões criadas`);

    // 2. Criar recursos
    console.log('Criando recursos...');
    const createdResources = await Resource.insertMany(resources);
    console.log(`${createdResources.length} recursos criados`);

    // 3. Criar papéis
    console.log('Criando papéis...');
    const createdRoles = [];
    
    for (const roleData of roles) {
      const role = await Role.create(roleData);
      createdRoles.push(role);
      
      // Se for o papel de admin, atribuir todas as permissões com todos os recursos
      if (roleData.name === 'admin') {
        const permissionEntries = [];
        
        for (const permission of createdPermissions) {
          // Adicionar permissão com todos os recursos relevantes dependendo da categoria
          const permissionResources = [];
          
          for (const resource of createdResources) {
            // Atribuir recursos com base na categoria da permissão
            if (
              (permission.category === 'user' && (resource.path.includes('users') || resource.path.includes('admin/users'))) ||
              (permission.category === 'product' && (resource.path.includes('products') || resource.path.includes('admin/products'))) ||
              (permission.category === 'order' && (resource.path.includes('orders') || resource.path.includes('admin/orders'))) ||
              (permission.category === 'delivery' && resource.path.includes('delivery')) ||
              (permission.category === 'report' && (resource.path.includes('reports') || resource.path.includes('admin/reports'))) ||
              (permission.category === 'system')
            ) {
              permissionResources.push({
                resource: resource._id,
                conditions: {}
              });
            }
          }
          
          permissionEntries.push({
            permission: permission._id,
            resources: permissionResources
          });
        }
        
        // Atualizar o papel com todas as permissões
        role.permissions = permissionEntries;
        await role.save();
      }
      
      // Para o papel de gerente, atribuir permissões limitadas
      if (roleData.name === 'gerente') {
        const permissionEntries = [];
        const allowedPermissionCodes = [
          'USER_VIEW', 'USER_EDIT',
          'PRODUCT_VIEW', 'PRODUCT_EDIT',
          'ORDER_VIEW', 'ORDER_CREATE', 'ORDER_PROCESS',
          'DELIVERY_VIEW', 'DELIVERY_MANAGE',
          'REPORT_VIEW', 'REPORT_EXPORT'
        ];
        
        for (const permission of createdPermissions) {
          if (allowedPermissionCodes.includes(permission.code)) {
            // Adicionar permissão com todos os recursos relevantes
            const permissionResources = [];
            
            for (const resource of createdResources) {
              // Lógica similar à do admin, mas só para os recursos permitidos
              if (
                (permission.category === 'user' && (resource.path.includes('users') || resource.path.includes('admin/users'))) ||
                (permission.category === 'product' && (resource.path.includes('products') || resource.path.includes('admin/products'))) ||
                (permission.category === 'order' && (resource.path.includes('orders') || resource.path.includes('admin/orders'))) ||
                (permission.category === 'delivery' && resource.path.includes('delivery')) ||
                (permission.category === 'report' && (resource.path.includes('reports') || resource.path.includes('admin/reports')))
              ) {
                permissionResources.push({
                  resource: resource._id,
                  conditions: {}
                });
              }
            }
            
            permissionEntries.push({
              permission: permission._id,
              resources: permissionResources
            });
          }
        }
        
        // Atualizar o papel com as permissões permitidas
        role.permissions = permissionEntries;
        await role.save();
      }
      
      // Para o papel de vendedor, atribuir permissões específicas de vendas
      if (roleData.name === 'vendedor') {
        const permissionEntries = [];
        const allowedPermissionCodes = [
          'PRODUCT_VIEW',
          'ORDER_VIEW', 'ORDER_CREATE', 'ORDER_PROCESS',
          'DELIVERY_VIEW'
        ];
        
        for (const permission of createdPermissions) {
          if (allowedPermissionCodes.includes(permission.code)) {
            // Adicionar permissão com recursos relevantes
            const permissionResources = [];
            
            for (const resource of createdResources) {
              if (
                (permission.category === 'product' && resource.path.includes('products')) ||
                (permission.category === 'order' && resource.path.includes('orders')) ||
                (permission.category === 'delivery' && resource.path.includes('delivery'))
              ) {
                permissionResources.push({
                  resource: resource._id,
                  conditions: {}
                });
              }
            }
            
            permissionEntries.push({
              permission: permission._id,
              resources: permissionResources
            });
          }
        }
        
        // Atualizar o papel com as permissões permitidas
        role.permissions = permissionEntries;
        await role.save();
      }
      
      // Para o papel de estoquista, atribuir permissões específicas de estoque
      if (roleData.name === 'estoquista') {
        const permissionEntries = [];
        const allowedPermissionCodes = [
          'PRODUCT_VIEW', 'PRODUCT_EDIT'
        ];
        
        for (const permission of createdPermissions) {
          if (allowedPermissionCodes.includes(permission.code)) {
            // Adicionar permissão com recursos relevantes
            const permissionResources = [];
            
            for (const resource of createdResources) {
              if (permission.category === 'product' && resource.path.includes('products')) {
                permissionResources.push({
                  resource: resource._id,
                  conditions: {}
                });
              }
            }
            
            permissionEntries.push({
              permission: permission._id,
              resources: permissionResources
            });
          }
        }
        
        // Atualizar o papel com as permissões permitidas
        role.permissions = permissionEntries;
        await role.save();
      }
    }
    
    console.log(`${createdRoles.length} papéis criados`);

    // 4. Atualizar usuários existentes para o novo modelo de papéis
    console.log('Atualizando usuários para o novo modelo RBAC...');
    
    // Encontrar o papel de admin
    const adminRole = await Role.findOne({ name: 'admin' });
    const userRole = await Role.findOne({ name: 'cliente' });
    
    if (adminRole && userRole) {
      // Atualizar todos os usuários com papel 'admin' para o novo modelo
      const adminUsers = await User.find({ role: 'admin' });
      for (const user of adminUsers) {
        // Verificar se o usuário já tem o papel atribuído
        const hasAdminRole = user.roles && user.roles.some(r => 
          r.role.toString() === adminRole._id.toString() && r.scope === 'global'
        );
        
        if (!hasAdminRole) {
          user.roles = user.roles || [];
          user.roles.push({
            role: adminRole._id,
            assignedAt: new Date(),
            scope: 'global'
          });
          await user.save();
        }
      }
      console.log(`${adminUsers.length} usuários admin atualizados`);
      
      // Atualizar todos os usuários com papel 'user' para o novo modelo
      const normalUsers = await User.find({ role: 'user' });
      for (const user of normalUsers) {
        // Verificar se o usuário já tem o papel atribuído
        const hasUserRole = user.roles && user.roles.some(r => 
          r.role.toString() === userRole._id.toString() && r.scope === 'global'
        );
        
        if (!hasUserRole) {
          user.roles = user.roles || [];
          user.roles.push({
            role: userRole._id,
            assignedAt: new Date(),
            scope: 'global'
          });
          await user.save();
        }
      }
      console.log(`${normalUsers.length} usuários normais atualizados`);
    }

    // 5. Criar um admin padrão se não existir
    const adminEmail = 'admin@mercearia.com';
    let adminUser = await User.findOne({ email: adminEmail });
    
    if (!adminUser) {
      console.log('Criando usuário admin padrão...');
      
      // Gerar hash da senha
      const passwordHash = await bcrypt.hash('admin@123', config.auth.password.saltRounds);
      
      // Criar usuário admin
      adminUser = await User.create({
        email: adminEmail,
        password: passwordHash,
        role: 'admin',
        verified: true,
        active: true,
        name: 'Administrador',
        surname: 'Sistema',
        roles: [{
          role: adminRole._id,
          assignedAt: new Date(),
          scope: 'global'
        }]
      });
      
      console.log('Usuário admin padrão criado');
    }

    console.log('Seeding RBAC concluído com sucesso!');
  } catch (error) {
    console.error('Erro ao fazer seed dos dados RBAC:', error);
  } finally {
    // Fechar conexão com o banco de dados
    await mongoose.disconnect();
    console.log('Conexão com MongoDB fechada');
  }
};

// Executar o seed
seedRbacData();