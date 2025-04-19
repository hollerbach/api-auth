// src/infrastructure/external/mail.service.js
const nodemailer = require('nodemailer');
const config = require('../config');
const logger = require('../logging/logger');
const { InternalServerError } = require('../../shared/errors/api-error');

/**
 * Serviço para envio de e-mails
 */
class MailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.auth.user,
        pass: config.email.auth.pass
      }
    });

    // Verificar conexão com serviço de email
    this.transporter
      .verify()
      .then(() => logger.info('Conexão com servidor de email estabelecida'))
      .catch(err => logger.error(`Erro ao conectar com servidor de email: ${err.message}`));
  }

  /**
   * Método base para envio de emails
   * @param {Object} mailOptions Opções do email a ser enviado
   * @returns {Promise<Object>} Informações do email enviado
   */
  async sendMail(mailOptions) {
    try {
      const info = await this.transporter.sendMail({
        from: config.email.from,
        ...mailOptions
      });

      logger.info(`Email enviado: ${info.messageId} para ${mailOptions.to}`);
      return info;
    } catch (error) {
      logger.error(`Erro ao enviar email para ${mailOptions.to}: ${error.message}`);
      throw new InternalServerError('Erro ao enviar email');
    }
  }

  /**
   * Envia email de verificação
   * @param {string} to Destinatário
   * @param {string} token Token de verificação
   */
  async sendVerificationEmail(to, token) {
    const verificationUrl = `${config.app.baseUrl}/api/auth/verify-email?token=${token}`;

    const mailOptions = {
      to,
      subject: 'Confirme seu cadastro na Mercearia Digital',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Confirmação de Cadastro</h2>
          <p>Obrigado por se cadastrar na Mercearia Digital.</p>
          <p>Clique no botão abaixo para confirmar seu endereço de e-mail:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Confirmar E-mail
            </a>
          </div>
          <p>Ou copie e cole o link abaixo no seu navegador:</p>
          <p>${verificationUrl}</p>
          <p>Este link expira em 30 minutos.</p>
          <p>Se você não solicitou este cadastro, por favor ignore este e-mail.</p>
          <hr style="border: 1px solid #f5f5f5; margin: 20px 0;">
          <p style="color: #7f8c8d; font-size: 12px;">
            © ${new Date().getFullYear()} Mercearia Digital. Todos os direitos reservados.
          </p>
        </div>
      `,
      text: `
        Confirmação de Cadastro
        
        Obrigado por se cadastrar na Mercearia Digital.
        
        Acesse o link abaixo para confirmar seu e-mail:
        ${verificationUrl}
        
        Este link expira em 30 minutos.
        
        Se você não solicitou este cadastro, por favor ignore este e-mail.
      `
    };

    return await this.sendMail(mailOptions);
  }

  /**
   * Envia email de redefinição de senha
   * @param {string} to Destinatário
   * @param {string} token Token de redefinição
   */
  async sendResetPasswordEmail(to, token) {
    const resetUrl = `${config.app.frontendUrl || config.app.baseUrl}/reset-password?token=${token}`;

    const mailOptions = {
      to,
      subject: 'Redefinição de senha - Mercearia Digital',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Redefinição de Senha</h2>
          <p>Você solicitou a redefinição da sua senha na Mercearia Digital.</p>
          <p>Clique no botão abaixo para criar uma nova senha:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Redefinir Senha
            </a>
          </div>
          <p>Ou copie e cole o link abaixo no seu navegador:</p>
          <p>${resetUrl}</p>
          <p>Este link expira em 15 minutos.</p>
          <p>Se você não solicitou esta redefinição, por favor ignore este e-mail ou entre em contato conosco se tiver alguma dúvida.</p>
          <hr style="border: 1px solid #f5f5f5; margin: 20px 0;">
          <p style="color: #7f8c8d; font-size: 12px;">
            © ${new Date().getFullYear()} Mercearia Digital. Todos os direitos reservados.
          </p>
        </div>
      `,
      text: `
        Redefinição de Senha
        
        Você solicitou a redefinição da sua senha na Mercearia Digital.
        
        Acesse o link abaixo para criar uma nova senha:
        ${resetUrl}
        
        Este link expira em 15 minutos.
        
        Se você não solicitou esta redefinição, por favor ignore este e-mail ou entre em contato conosco se tiver alguma dúvida.
      `
    };

    return await this.sendMail(mailOptions);
  }

  /**
   * Envia códigos de recuperação 2FA para o usuário
   * @param {string} to Destinatário
   * @param {Array<string>} recoveryCodes Códigos de recuperação
   */
  async sendRecoveryCodes(to, recoveryCodes) {
    const codesHtml = recoveryCodes
      .map(code => `<li style="font-family: monospace; margin: 5px 0;">${code}</li>`)
      .join('');

    const codesText = recoveryCodes.join('\n');

    const mailOptions = {
      to,
      subject: 'Seus códigos de recuperação 2FA - Mercearia Digital',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Códigos de Recuperação 2FA</h2>
          <p>Você ativou a autenticação de dois fatores em sua conta da Mercearia Digital.</p>
          <p>Guarde estes códigos de recuperação em um local seguro. Eles permitem que você acesse sua conta caso perca acesso ao seu dispositivo de autenticação:</p>
          <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <ul style="list-style-type: none; padding: 0;">
              ${codesHtml}
            </ul>
          </div>
          <p><strong>IMPORTANTE:</strong> Cada código pode ser usado apenas uma vez e substituem a necessidade do código 2FA.</p>
          <p>Se você não solicitou a ativação de 2FA, por favor entre em contato conosco imediatamente.</p>
          <hr style="border: 1px solid #f5f5f5; margin: 20px 0;">
          <p style="color: #7f8c8d; font-size: 12px;">
            © ${new Date().getFullYear()} Mercearia Digital. Todos os direitos reservados.
          </p>
        </div>
      `,
      text: `
        Códigos de Recuperação 2FA
        
        Você ativou a autenticação de dois fatores em sua conta da Mercearia Digital.
        
        Guarde estes códigos de recuperação em um local seguro. Eles permitem que você acesse sua conta caso perca acesso ao seu dispositivo de autenticação:
        
        ${codesText}
        
        IMPORTANTE: Cada código pode ser usado apenas uma vez e substituem a necessidade do código 2FA.
        
        Se você não solicitou a ativação de 2FA, por favor entre em contato conosco imediatamente.
      `
    };

    return await this.sendMail(mailOptions);
  }
}

module.exports = new MailService();