// ============================================================================
//  auth.js  -  Gestion de identidad y acceso (IAM)
// ============================================================================
//
//  Middleware que exige un token JWT valido emitido por Keycloak.

const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const config = require('./config');

// [FIX H-06] Se elimina la verificacion insegura (alg=none, HS256 con secreto
//   quemado): ahora se valida la firma contra las llaves publicas (JWKS) de
//   Keycloak y solo se acepta RS256. CWE-347 / CWE-287 remediados.
const verificarJWT = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/certs`,
  }),
  issuer: `${config.KEYCLOAK_ISSUER_URL}/realms/${config.KEYCLOAK_REALM}`,
  algorithms: ['RS256'],
  requestProperty: 'usuario',
});

function requiereAuth(req, res, next) {
  // Si el control de acceso esta apagado (modo demo), deja pasar a cualquiera.
  if (!config.AUTH_ENABLED) {
    return next();
  }

  return verificarJWT(req, res, (err) => {
    if (err) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    return next();
  });
}

module.exports = { requiereAuth };
