// ============================================================================
//  config.js  -  Configuracion del servicio
//  >>> VERSION INSEGURA <<<  Contiene secretos quemados a proposito.
// ============================================================================

// [VULN-2] Secretos quemados en el codigo (hardcoded credentials).
//   Nunca deben vivir en el repositorio: los detecta Gitleaks y Semgrep.
//   La solucion es leerlos de variables de entorno (process.env) y NUNCA
//   versionarlos. Las llaves de abajo son de ejemplo/ficticias.
//   CWE-798 (Use of Hard-coded Credentials) / CWE-259

const config = {
  // Credencial de nube ficticia (patron que Gitleaks reconoce como AWS)
 // AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
  //AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // Secreto para firmar/verificar tokens propios: quemado (mal)
  //JWT_SECRET: 'sup3r-s3cr3t0-cib204-no-lo-cambies',

  // Cadena de conexion con contrasena en claro (mal)
  //DATABASE_URL: 'mysql://root:Admin1234@localhost:3306/appmovil',

  // Control de acceso DESACTIVADO por defecto (mal)
  //AUTH_ENABLED: process.env.AUTH_ENABLED === 'true' ? true : false,

  // Parametros de Keycloak (IAM)
  //KEYCLOAK_URL: process.env.KEYCLOAK_URL || 'http://localhost:8080',
  //KEYCLOAK_REALM: process.env.KEYCLOAK_REALM || 'appmovil',

  //PUERTO: process.env.PORT || 3000,
//};

  // [FIX H-01] Credenciales ya no quedan escritas en el codigo: se leen
  //   del entorno (variables de entorno / GitHub Secrets). CWE-798 remediado.
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,

  JWT_SECRET: process.env.JWT_SECRET,

  DATABASE_URL: process.env.DATABASE_URL,

  // Control de acceso DESACTIVADO por defecto (mal)
  AUTH_ENABLED: process.env.AUTH_ENABLED === 'true' ? true : false,

  // Parametros de Keycloak (IAM)
  KEYCLOAK_URL: process.env.KEYCLOAK_URL || 'http://localhost:8080',
  KEYCLOAK_REALM: process.env.KEYCLOAK_REALM || 'appmovil',

  PUERTO: process.env.PORT || 3000,
};

module.exports = config;
