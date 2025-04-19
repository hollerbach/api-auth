// src/infrastructure/security/passport.config.js
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const userRepository = require('../database/mongodb/repositories/user.repository');
const config = require('../config');
const logger = require('../logging/logger');
const { NotFoundError } = require('../../shared/errors/api-error');
const crypto = require('crypto');

/**
 * Configura as estratégias de autenticação do Passport
 * @param {Object} passport Instância do Passport
 */
module.exports = (passport) => {
  // Configurar a estratégia JWT
  const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: config.auth.jwt.secret,
    ignoreExpiration: false
  };

  passport.use(
    new JwtStrategy(jwtOptions, async (payload, done) => {
      try {
        // Verificar se o token está na blacklist
        const isBlacklisted = await userRepository.isTokenBlacklisted(payload.jti);
        if (isBlacklisted) {
          return done(null, false, { message: 'Token inválido' });
        }

        // Buscar usuário pelo ID
        const user = await userRepository.findById(payload.id);

        if (!user) {
          return done(null, false, { message: 'Usuário não encontrado' });
        }

        if (!user.verified) {
          return done(null, false, { message: 'Conta não verificada' });
        }

        if (!user.active) {
          return done(null, false, { message: 'Conta desativada' });
        }

        // Retornar informações básicas do usuário
        return done(null, {
          id: user.id,
          email: user.email,
          role: user.role
        });
      } catch (error) {
        logger.error(`Erro na autenticação JWT: ${error.message}`);
        return done(error, false);
      }
    })
  );

  // Configurar a estratégia OAuth Google
  if (config.oauth?.google?.clientId && config.oauth?.google?.clientSecret) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: config.oauth.google.callbackUrl || `${config.app.url}/api/auth/google/callback`,
          scope: ['profile', 'email']
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            // Verificar se o usuário já existe com este googleId
            let user = await userRepository.findByOAuthId('google', profile.id);

            // Se não existir, verificar se o email já está registrado
            if (!user && profile.emails && profile.emails.length > 0) {
              const email = profile.emails[0].value;
              user = await userRepository.findByEmail(email);

              // Se o usuário existe mas não tem o Google ID, vincular
              if (user) {
                user.linkOAuthAccount('google', {
                  id: profile.id,
                  email: email,
                  name: profile.displayName,
                  picture: profile.photos?.[0]?.value
                });
                
                // Usuários do Google são considerados verificados
                if (!user.verified) {
                  user.verifyEmail();
                }
                
                await userRepository.save(user);
                logger.info(`Usuário ${email} vinculou conta do Google`);
              }
            }

            // Se ainda não existe, criar um novo usuário
            if (!user) {
              const email = profile.emails?.[0]?.value;
              if (!email) {
                return done(new NotFoundError('Email não fornecido pelo Google'));
              }

              // Gerar senha aleatória segura (o usuário não a utilizará)
              const randomPassword = crypto.randomBytes(20).toString('hex');

              // Criar novo usuário
              user = await userRepository.create({
                email,
                password: randomPassword,
                role: 'user',
                verified: true, // Contas OAuth são verificadas por padrão
                oauth: {
                  google: {
                    id: profile.id,
                    email: email,
                    name: profile.displayName,
                    picture: profile.photos?.[0]?.value
                  }
                },
                name: profile.displayName || profile.name?.givenName,
                surname: profile.name?.familyName
              });

              logger.info(`Novo usuário criado via Google: ${email}`);
            }

            return done(null, user);
          } catch (error) {
            logger.error(`Erro na autenticação Google: ${error.message}`);
            return done(error);
          }
        }
      )
    );
  }

  // Serialização (necessária mesmo sem sessões para alguns casos)
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await userRepository.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  logger.info('Passport configurado com sucesso');
};