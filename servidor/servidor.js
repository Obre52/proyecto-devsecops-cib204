// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION INSEGURA (rama inseguro) <<<
//
//  Endpoints:
//    GET  /salud       -> estado del servicio
//    GET  /llave       -> entrega la llave publica
//    POST /cifrar      -> cifra un texto
//    POST /descifrar   -> descifra un texto
//    GET  /buscar      -> consulta la bitacora (demostracion de SQLi)
//    POST /calcular    -> "utilidad" de calculo (demostracion de eval)
//    GET  /diagnostico -> ejecuta un ping (demostracion de command injection)
// ============================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
//const { exec } = require('child_process');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requiereAuth } = require('./auth');
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });

// [FIX H-14] CSRF: esta API es "stateless" (sin cookies de sesion). Todas las
//   operaciones que cambian estado (/cifrar, /descifrar) exigen el JWT en la
//   cabecera Authorization, que un navegador NUNCA adjunta automaticamente en
//   una peticion cross-site (a diferencia de una cookie). El CSRF clasico no
//   aplica a autenticacion por Bearer token + CORS restringido (ver H-10).
//   CWE-352 remediado por diseno; se documenta para Semgrep.
// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
const app = express();
app.use(express.json());

// [FIX H-10] CORS restringido a un origen de confianza en vez de aceptar
//   cualquiera ("*"). CWE-942 remediado.
app.use(cors({ origin: config.ORIGEN_PERMITIDO }));

// [FIX H-09] Cabeceras de seguridad con Helmet: incluye por defecto
//   Content-Security-Policy con frame-ancestors y form-action (antes
//   ausentes), X-Content-Type-Options, etc. Se agrega ademas Permissions-Policy
//   explicito, que Helmet ya no establece por defecto. CWE-693 remediado.
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  next();
});

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'inseguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

app.post('/cifrar', limiter, requiereAuth, (req, res) => {
  try {
    // [FIX H-11] Validacion de tipo y longitud (1-180 caracteres) del texto.
    //   CWE-20 remediado.
    const texto = req.body.texto;
    if (typeof texto !== 'string' || texto.length < 1 || texto.length > 180) {
      return res.status(400).json({ error: 'Texto invalido: debe ser una cadena de 1 a 180 caracteres' });
    }
    const resultado = cifrado.cifrar(texto, llaves.publicKey);
    res.json({ cifrado: resultado });
  } catch (e) {
    // [FIX H-12] Ya no se expone el stack trace al cliente. CWE-209 remediado.
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/descifrar', limiter, requiereAuth, (req, res) => {
  try {
    const cifradoTxt = req.body.cifrado;
    if (typeof cifradoTxt !== 'string' || cifradoTxt.length < 1) {
      return res.status(400).json({ error: 'Entrada invalida' });
    }
    const resultado = cifrado.descifrar(cifradoTxt, llaves.privateKey);
    res.json({ descifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Demostracion de INYECCION SQL (CWE-89).
app.get('/buscar', (req, res) => {
  const nombre = req.query.nombre || '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [FIX H-03] Se elimina eval(): ya no se evalua una expresion como codigo,
//   se recibe un arreglo de numeros validado y se suma. CWE-95 remediado.
app.post('/calcular', (req, res) => {
  const nums = Array.isArray(req.body.numeros) ? req.body.numeros : [];
  if (!nums.every(n => typeof n === 'number'))
    return res.status(400).json({ error: 'Entrada invalida' });
  res.json({ resultado: nums.reduce((a, b) => a + b, 0) });
});

const { execFile } = require('child_process');

app.get('/diagnostico', limiter, (req, res) => {
  const host = req.query.host || '127.0.0.1';
  if (!/^[a-zA-Z0-9.-]{1,64}$/.test(host))
    return res.status(400).json({ error: 'Host invalido' });
  execFile('ping', ['-c', '1', host], (e, out) => res.json({ salida: out }));
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;
