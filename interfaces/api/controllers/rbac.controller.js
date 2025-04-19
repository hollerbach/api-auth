// src/interfaces/api/controllers/rbac.controller.js
const rbacRepository = require('../../../infrastructure/database/mongodb/repositories/rbac.repository');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const { CreateRoleUseCase, AssignRoleToUserUseCase, CreatePermissionUseCase, AddPermissionToRoleUseCase } = require('../../../domain/rbac/use-cases/rbac.use-cases');
const logger = require('../../../infrastructure/logging/logger');

// Auditoria (opcional)
let auditService;
try {
  auditService = require('../../../infrastructure/logging/audit.service');
} catch (error) {
  console.warn('Serviço de auditoria não disponível');
}

/**
 * Controlador para gerenciamento de RBAC
 */
class RbacController {
  /**
   * Cria um novo papel
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async createRole(req, res) {
    const createRoleUseCase = new CreateRoleUseCase(
      rbacRepository,
      auditService
    );

    const role = await createRoleUseCase.execute(req.body, req.user);

    res.status(201).json(role);
  }

  /**
   * Lista todos os papéis
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getAllRoles(req, res) {
    const { page, limit, sort, order, search, isSystem } = req.sanitizedQuery;

    const options = {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 20,
      sort: sort || 'name',
      order: order || 'asc',
      search: search || null
    };

    if (isSystem !== undefined) {
      options.isSystem = isSystem === 'true';
    }

    const result = await rbacRepository.findAllRoles(options);

    res.status(200).json(result);
  }

  /**
   * Obtém um papel por ID
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getRoleById(req, res) {
    const { id } = req.params;
    const role = await rbacRepository.findRoleById(id);

    if (!role) {
      return res.status(404).json({ message: 'Papel não encontrado' });
    }

    res.status(200).json(role);
  }

  /**
   * Atualiza um papel
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async updateRole(req, res) {
    const { id } = req.params;
    const { name, description } = req.body;

    // Não permitir atualização de isSystem via API
    const roleData = {
      name,
      description
    };

    const updatedRole = await rbacRepository.updateRole(id, roleData);

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'ROLE_UPDATED',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { roleId: id, roleData }
      });
    }

    res.status(200).json(updatedRole);
  }

  /**
   * Remove um papel
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async deleteRole(req, res) {
    const { id } = req.params;

    await rbacRepository.deleteRole(id);

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'ROLE_DELETED',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { roleId: id }
      });
    }

    res.status(200).json({ message: 'Papel removido com sucesso' });
  }

  /**
   * Cria uma nova permissão
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async createPermission(req, res) {
    const createPermissionUseCase = new CreatePermissionUseCase(
      rbacRepository,
      auditService
    );

    const permission = await createPermissionUseCase.execute(req.body, req.user);

    res.status(201).json(permission);
  }

  /**
   * Lista todas as permissões
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getAllPermissions(req, res) {
    const { page, limit, sort, order, search, category } = req.sanitizedQuery;

    const options = {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 20,
      sort: sort || 'name',
      order: order || 'asc',
      search: search || null,
      category: category || null
    };

    const result = await rbacRepository.findAllPermissions(options);

    res.status(200).json(result);
  }

  /**
   * Obtém uma permissão por ID
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getPermissionById(req, res) {
    const { id } = req.params;
    const permission = await rbacRepository.findPermissionById(id);

    if (!permission) {
      return res.status(404).json({ message: 'Permissão não encontrada' });
    }

    res.status(200).json(permission);
  }

  /**
   * Atualiza uma permissão
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async updatePermission(req, res) {
    const { id } = req.params;
    const { name, description, category } = req.body;

    // Não permitir atualização do código via API
    const permissionData = {
      name,
      description,
      category
    };

    const updatedPermission = await rbacRepository.updatePermission(id, permissionData);

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'PERMISSION_UPDATED',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { permissionId: id, permissionData }
      });
    }

    res.status(200).json(updatedPermission);
  }

  /**
   * Remove uma permissão
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async deletePermission(req, res) {
    const { id } = req.params;

    await rbacRepository.deletePermission(id);

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'PERMISSION_DELETED',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { permissionId: id }
      });
    }

    res.status(200).json({ message: 'Permissão removida com sucesso' });
  }

  /**
   * Adiciona uma permissão a um papel
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async addPermissionToRole(req, res) {
    const { roleId, permissionId } = req.params;
    const { resources } = req.body;

    const addPermissionUseCase = new AddPermissionToRoleUseCase(
      rbacRepository,
      auditService
    );

    const updatedRole = await addPermissionUseCase.execute(
      roleId,
      permissionId,
      resources || [],
      req.user
    );

    res.status(200).json(updatedRole);
  }

  /**
   * Remove uma permissão de um papel
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async removePermissionFromRole(req, res) {
    const { roleId, permissionId } = req.params;

    const updatedRole = await rbacRepository.removePermissionFromRole(roleId, permissionId);

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'PERMISSION_REMOVED_FROM_ROLE',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { roleId, permissionId }
      });
    }

    res.status(200).json(updatedRole);
  }

  /**
   * Atribui um papel a um usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async assignRoleToUser(req, res) {
    const { userId, roleId } = req.params;
    const { scope, scopeId } = req.body;

    const assignRoleUseCase = new AssignRoleToUserUseCase(
      userRepository,
      rbacRepository,
      auditService
    );

    const options = {
      scope: scope || 'global',
      scopeId: scopeId || null
    };

    const user = await assignRoleUseCase.execute(userId, roleId, options, req.user);

    res.status(200).json({
      message: 'Papel atribuído com sucesso',
      user: user.toSafeObject(true) // true = admin view
    });
  }

  /**
   * Remove um papel de um usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async removeRoleFromUser(req, res) {
    const { userId, roleId } = req.params;
    const { scope, scopeId } = req.body;

    const user = await userRepository.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const options = {
      scope: scope || 'global',
      scopeId: scopeId || null
    };

    const removed = await user.removeRole(roleId, options);
    
    if (!removed) {
      return res.status(404).json({ message: 'Papel não encontrado no usuário' });
    }

    // Registrar na auditoria
    if (auditService) {
      await auditService.log({
        action: 'ROLE_REMOVED_FROM_USER',
        userId: req.user.id,
        userEmail: req.user.email,
        details: { 
          targetUserId: userId,
          roleId,
          scope: options.scope,
          scopeId: options.scopeId
        }
      });
    }

    res.status(200).json({
      message: 'Papel removido com sucesso',
      user: user.toSafeObject(true) // true = admin view
    });
  }

  /**
   * Lista os papéis de um usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getUserRoles(req, res) {
    const { userId } = req.params;

    const user = await userRepository.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const userWithRoles = await user.getRoles();

    res.status(200).json({
      userId,
      email: user.email,
      roles: userWithRoles.roles
    });
  }
}

module.exports = new RbacController();