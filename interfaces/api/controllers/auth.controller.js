// src/interfaces/api/controllers/auth.controller.js
const AuthUseCaseFactory = require('../../../domain/auth/factories/auth-use-case.factory');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const mailService = require('../../../infrastructure/external/mail.service');
const tokenService = require('../../../infrastructure/security/token.service');
const twoFactorService = require('../../../infrastructure/security/two-factor.service');
const config = require('../../../infrastructure/config');
const securityConfig = require('../../../infrastructure/security/security.config');
const crypto = require('crypto');

// Auditoria (opcional)
let auditService;
try {
  auditService = require('../../../infrastructure/logging/audit.service');
} catch (error) {
  console.warn('Serviço de auditoria não disponível');
}

/**
 * Controlador para rotas de autenticação
 */
class AuthController {
  /**
   * Registra um novo usuário
   */
  async register(req, res) {
    const registerUseCase = AuthUseCaseFactory.createRegisterUserUseCase();
    const result = await registerUseCase.execute(req.body, req.ip);

    res.status(201).json({
      message: 'Usuário registrado com sucesso. Verifique seu e-mail para ativar a conta.',
      user: result.user
    });
  }

  /**
   * Verifica o e-mail do usuário
   */
  async verifyEmail(req, res) {
    const { token } = req.sanitizedQuery;
    const verifyEmailUseCase = AuthUseCaseFactory.createVerifyEmailUseCase();
    const result = await verifyEmailUseCase.execute(token, req.ip);

    res.status(200).json(result);
  }

  /**
   * Autentica um usuário
   */
  async login(req, res) {
    const { email, password } = req.body;
    const ipAddress = req.ip;

    // Buscar usuário por email
    const user = await userRepository.findByEmail(email);

    // Verificar se o usuário existe e se está verificado
    if (!user || !user.verified) {
      if (auditService && user) {
        await auditService.log({
          action: 'LOGIN_FAILED',
          userId: user.id,
          userEmail: email,
          ipAddress,
          details: { reason: 'Conta não verificada' }
        });
      }

      // Não revelar se o usuário existe, apenas retornar erro genérico
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Verificar se a conta está bloqueada
    if (user.isLocked()) {
      await auditService?.log({
        action: 'LOGIN_FAILED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: { reason: 'Conta bloqueada' }
      });

      return res.status(429).json({
        message: 'Conta temporariamente bloqueada por excesso de tentativas. Tente novamente mais tarde.',
        lockUntil: user.lockUntil
      });
    }

    // Verificar senha
    const isPasswordValid = await userRepository.validatePassword(user.id, password);

    if (!isPasswordValid) {
      // Incrementar contador de falhas de login
      const updatedUser = await userRepository.incrementLoginAttempts(user.id);

      await auditService?.log({
        action: 'LOGIN_FAILED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: {
          reason: 'Senha inválida',
          attemptsRemaining: Math.max(0, 5 - updatedUser.loginAttempts),
          isLocked: updatedUser.isLocked()
        }
      });

      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Resetar contagem de tentativas após login bem-sucedido
    await userRepository.resetLoginAttempts(user.id);

    // Verificar se 2FA está ativado
    if (user.twoFactorEnabled) {
      const tempToken = tokenService.generateTempToken({ id: user.id, email: user.email });

      await auditService?.log({
        action: 'LOGIN_2FA_REQUIRED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: { success: true }
      });

      return res.status(206).json({
        message: '2FA necessário',
        tempToken
      });
    }

    // Gerar tokens para usuário autenticado
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    res.cookie('refreshToken', refreshToken.token, securityConfig.cookieOptions.refreshToken);

    // Registrar na auditoria
    await auditService?.log({
      action: 'LOGIN',
      userId: user.id,
      userEmail: user.email,
      ipAddress,
      details: { user2FA: user.twoFactorEnabled }
    });

    res.status(200).json({
      accessToken,
      user: user.toSafeObject()
    });
  }

  /**
   * Verifica o token 2FA e completa o login
   */
  async verify2FA(req, res) {
    const { token, tempToken } = req.body;
    const ipAddress = req.ip;

    // Usar caso de uso para verificação 2FA
    const verify2FAUseCase = AuthUseCaseFactory.createVerify2FAUseCase();
    const result = await verify2FAUseCase.execute(token, tempToken, ipAddress);

    // Definir cookie HTTP-only para refresh token
    res.cookie('refreshToken', result.refreshToken, securityConfig.cookieOptions.refreshToken);

    // Retornar apenas o token de acesso e usuário (não o refresh token)
    res.status(200).json({
      accessToken: result.accessToken,
      user: result.user
    });
  }

  /**
   * Autentica com código de recuperação 2FA
   */
  async verify2FARecovery(req, res) {
    const { code, tempToken } = req.body;
    const ipAddress = req.ip;

    // Verificar e decodificar o token temporário
    const decoded = tokenService.verifyAccessToken(tempToken);

    if (!decoded || !decoded.is2FA) {
      return res.status(400).json({ message: 'Token temporário inválido' });
    }

    const user = await userRepository.findById(decoded.id);

    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({ message: '2FA não está habilitado para este usuário' });
    }

    // Verificar o código de recuperação
    const recoveryCodeValid = user.validateRecoveryCode(code);

    if (!recoveryCodeValid) {
      await auditService?.log({
        action: 'LOGIN_2FA_RECOVERY_FAILED',
        userId: user.id,
        userEmail: user.email,
        ipAddress
      });

      return res.status(401).json({ message: 'Código de recuperação inválido' });
    }

    // Salvar mudanças (marcar código como usado)
    await userRepository.save(user);

    // Gerar tokens para usuário autenticado com 2FA
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    res.cookie('refreshToken', refreshToken.token, securityConfig.cookieOptions.refreshToken);

    // Registrar na auditoria
    await auditService?.log({
      action: 'LOGIN_2FA_RECOVERY_SUCCESS',
      userId: user.id,
      userEmail: user.email,
      ipAddress
    });

    res.status(200).json({
      accessToken,
      user: user.toSafeObject(),
      recoveryCodesRemaining: user.recoveryCodes.filter(c => !c.used).length
    });
  }

  /**
   * Configura a autenticação de dois fatores para um usuário
   */
  async setup2FA(req, res) {
    const userId = req.user.id;

    // Buscar usuário
    const user = await userRepository.findById(userId);

    // Gerar segredo para 2FA
    const secret = twoFactorService.generateSecret(user.email);

    // Atualizar usuário com segredo 2FA
    user.enable2FA(secret.base32);
    await userRepository.save(user);

    // Gerar QR Code para configuração
    const qrCode = await twoFactorService.generateQRCode(secret.otpauth_url);

    // Gerar códigos de recuperação
    const recoveryCodes = twoFactorService.generateRecoveryCodes();

    // Salvar códigos de recuperação
    user.setRecoveryCodes(recoveryCodes);
    await userRepository.save(user);

    // Enviar códigos por email como backup
    await mailService.sendRecoveryCodes(user.email, recoveryCodes);

    // Registrar na auditoria
    await auditService?.log({
      action: '2FA_SETUP',
      userId: user.id,
      userEmail: user.email,
      ipAddress: req.ip
    });

    res.status(200).json({
      qrCode,
      recoveryCodes,
      secret: config.app.env === 'development' ? secret.base32 : undefined // Enviar apenas em ambiente de desenvolvimento
    });
  }

  /**
   * Desativa a autenticação de dois fatores
   */
  async disable2FA(req, res) {
    const userId = req.user.id;
    const { token } = req.body;

    // Buscar usuário
    const user = await userRepository.findById(userId);

    // Verificar token antes de desativar
    const verified = twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      return res.status(401).json({ message: 'Código 2FA inválido' });
    }

    // Desativar 2FA
    user.disable2FA();
    await userRepository.save(user);

    // Registrar na auditoria
    await auditService?.log({
      action: '2FA_DISABLED',
      userId: user.id,
      userEmail: user.email,
      ipAddress: req.ip
    });

    res.status(200).json({ message: '2FA desativado com sucesso' });
  }

  /**
   * Realiza logout invalidando tokens
   */
  async logout(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    const refreshToken = req.cookies.refreshToken;
    const ipAddress = req.ip;

    // Usar caso de uso para logout
    const logoutUseCase = AuthUseCaseFactory.createLogoutUseCase();
    await logoutUseCase.execute(token, refreshToken, req.user, ipAddress);

    // Limpar cookie
    const cookieOptions = { ...securityConfig.cookieOptions.refreshToken, maxAge: 0 };
    res.clearCookie('refreshToken', cookieOptions);

    res.status(200).json({ message: 'Logout realizado com sucesso' });
  }

  /**
   * Atualiza tokens usando refresh token
   */
  async refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    const ipAddress = req.ip;

    // Usar caso de uso para refresh de tokens
    const refreshTokensUseCase = AuthUseCaseFactory.createRefreshTokensUseCase();
    const result = await refreshTokensUseCase.execute(refreshToken, ipAddress);

    // Atualizar cookie
    res.cookie('refreshToken', result.refreshToken, securityConfig.cookieOptions.refreshToken);

    res.status(200).json({ accessToken: result.accessToken });
  }

  /**
   * Solicita redefinição de senha
   */
  async requestPasswordReset(req, res) {
    const { email } = req.body;

    // Buscar usuário
    const user = await userRepository.findByEmail(email);

    // Se o usuário não existe, fingir que tudo correu bem
    // para não revelar se o email está cadastrado
    if (!user) {
      return res.status(200).json({
        message: 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado'
      });
    }

    // Gerar token de redefinição
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + config.auth.password.resetTokenExpiry);

    // Salvar token no usuário
    user.resetToken = resetToken;
    user.resetTokenExpires = resetTokenExpires;
    await userRepository.save(user);

    // Enviar e-mail com token
    await mailService.sendResetPasswordEmail(email, resetToken);

    // Registrar na auditoria
    await auditService?.log({
      action: 'PASSWORD_RESET_REQUEST',
      userId: user.id,
      userEmail: email,
      ipAddress: req.ip
    });

    res.status(200).json({
      message: 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado'
    });
  }

  /**
   * Redefine a senha usando token
   */
  async resetPassword(req, res) {
    const { token, newPassword } = req.body;

    // Buscar usuário com token válido
    const user = await userRepository.findByResetToken(token);

    if (!user) {
      return res.status(400).json({ message: 'Token inválido ou expirado' });
    }

    // Atualizar senha
    user.password = newPassword; // o hash será feito no repositório
    user.resetToken = null;
    user.resetTokenExpires = null;

    await userRepository.save(user);

    // Registrar na auditoria
    await auditService?.log({
      action: 'PASSWORD_RESET_COMPLETE',
      userId: user.id,
      userEmail: user.email,
      ipAddress: req.ip
    });

    res.status(200).json({ message: 'Senha redefinida com sucesso' });
  }

  /**
   * Processa o callback da autenticação Google
   */
  async googleCallback(req, res) {
    const ipAddress = req.ip;
    const user = req.user;

    if (!user) {
      return res.status(401).json({ message: 'Falha na autenticação com Google' });
    }

    // Gerar tokens
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    res.cookie('refreshToken', refreshToken.token, securityConfig.cookieOptions.refreshToken);

    // Registrar na auditoria
    await auditService?.log({
      action: 'LOGIN_GOOGLE',
      userId: user.id,
      userEmail: user.email,
      ipAddress
    });

    // Redirecionar para frontend com token
    const redirectUrl = `${config.oauth.google.redirectUrl}/login/oauth/success?token=${accessToken}`;
    res.redirect(redirectUrl);
  }
}

module.exports = new AuthController();