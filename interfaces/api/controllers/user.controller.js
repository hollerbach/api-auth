// src/interfaces/api/controllers/user.controller.js
const { UserNotFoundError } = require('../../../shared/errors/api-error');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Controlador para operações relacionadas a usuários
 */
class UserController {
  /**
   * Obtém o perfil do usuário atual
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getProfile(req, res) {
    const userId = req.user.id;
    const user = await userRepository.findById(userId);

    if (!user) {
      throw new UserNotFoundError('Usuário não encontrado');
    }

    res.status(200).json(user.toSafeObject());
  }

  /**
   * Atualiza o perfil do usuário atual
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async updateProfile(req, res) {
    const userId = req.user.id;
    const updates = req.body;

    // Evitar atualizações de campos sensíveis
    delete updates.password;
    delete updates.role; // Role só pode ser alterada por admin
    delete updates.verified;
    delete updates.twoFactorEnabled;
    delete updates.twoFactorSecret;

    const user = await userRepository.findById(userId);
    if (!user) {
      throw new UserNotFoundError('Usuário não encontrado');
    }

    // Atualizar campos permitidos
    user.update(updates);
    const updatedUser = await userRepository.save(user);

    logger.info(`Perfil atualizado para usuário ${userId}`);
    res.status(200).json(updatedUser.toSafeObject());
  }

  /**
   * Altera a senha do usuário atual
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async changePassword(req, res) {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    // Verificar senha atual
    const isValid = await userRepository.validatePassword(userId, currentPassword);
    if (!isValid) {
      throw new Error('Senha atual incorreta');
    }

    // Buscar usuário e atualizar senha
    const user = await userRepository.findById(userId);
    user.password = newPassword; // O hash será aplicado no repositório
    await userRepository.save(user);

    logger.info(`Senha alterada para usuário ${userId}`);
    res.status(200).json({ message: 'Senha alterada com sucesso' });
  }

  /**
   * Lista todos os usuários (somente admin)
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getAllUsers(req, res) {
    const { page = 1, limit = 20, sort = 'email', order = 'asc', search } = req.sanitizedQuery;

    const options = {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      sort,
      order,
      search
    };

    const result = await userRepository.findAll(options);

    // Converter para objetos seguros (sem dados sensíveis)
    const safeUsers = result.users.map(user => user.toSafeObject(true)); // true = admin view

    res.status(200).json({
      users: safeUsers,
      pagination: result.pagination
    });
  }

  /**
   * Obtém um usuário por ID (somente admin)
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getUserById(req, res) {
    const { id } = req.params;
    const user = await userRepository.findById(id);

    if (!user) {
      throw new UserNotFoundError('Usuário não encontrado');
    }

    // true = admin view (inclui campos adicionais)
    res.status(200).json(user.toSafeObject(true));
  }

  /**
   * Atualiza um usuário por ID (somente admin)
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async updateUser(req, res) {
    const { id } = req.params;
    const updates = req.body;

    // Não permitir atualização de campos sensíveis
    delete updates.password;
    delete updates.twoFactorSecret;

    const user = await userRepository.findById(id);
    if (!user) {
      throw new UserNotFoundError('Usuário não encontrado');
    }

    user.update(updates);
    const updatedUser = await userRepository.save(user);

    logger.info(`Usuário ${id} atualizado por ${req.user.id}`);
    res.status(200).json(updatedUser.toSafeObject(true));
  }

  /**
   * Desativa um usuário (não exclui)
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async deactivateUser(req, res) {
    const { id } = req.params;

    // Verificar se não está tentando desativar a si mesmo
    if (id === req.user.id) {
      throw new Error('Não é possível desativar seu próprio usuário');
    }

    const user = await userRepository.findById(id);
    if (!user) {
      throw new UserNotFoundError('Usuário não encontrado');
    }

    user.deactivate();
    await userRepository.save(user);

    logger.info(`Usuário ${id} desativado por ${req.user.id}`);
    res.status(200).json({ message: 'Usuário desativado com sucesso' });
  }
}

module.exports = new UserController();