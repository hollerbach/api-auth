// src/infrastructure/security/passport.config.js
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const userRepository = require('../database/mongodb/repositories/user.repository');
const config = require('../config');

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

        // O payload básico do JWT já contém id, email e role
        return done(null, {
          id: user.id,
          email: user.email,
          role: user.role
        });
      } catch (error) {
        return done(error, false);
      }
    })
  );

  // Configurar a estratégia OAuth Google (se as credenciais estiverem disponíveis)
  if (config.oauth?.google?.clientId && config.oauth?.google?.clientSecret) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: `${config.app.url}/api/v1/auth/google/callback`,
          scope: ['profile', 'email']
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            // Extrair informações do perfil
            const { id, emails, displayName, photos } = profile;
            
            if (!emails || !emails.length) {
              return done(null, false, { message: 'Email não fornecido pelo Google' });
            }

            const email = emails[0].value;
            const picture = photos && photos.length ? photos[0].value : null;

            // Verificar se o usuário já existe
            let user = await userRepository.findByEmail(email);

            if (user) {
              // Atualizar informações do OAuth se necessário
              if (!user.oauth?.google?.id) {
                user.oauth = {
                  ...(user.oauth || {}),
                  google: {
                    id,
                    email,
                    name: displayName,
                    picture
                  }
                };
                await userRepository.save(user);
              }
            } else {
              // Criar um novo usuário
              user = await userRepository.createWithOAuth({
                email,
                name: displayName,
                oauth: {
                  google: {
                    id,
                    email,
                    name: displayName,
                    picture
                  }
                },
                verified: true // Já verificado pelo Google
              });
            }

            return done(null, user);
          } catch (error) {
            return done(error, false);
          }
        }
      )
    );
  }
};