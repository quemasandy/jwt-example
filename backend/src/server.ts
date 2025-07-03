// ===================================================================================================
// 🌐 SERVIDOR DE AUTENTICACIÓN JWT - BACKEND COMPLETO
// ===================================================================================================

// ===================================================================================================
// 📦 IMPORTACIONES Y DEPENDENCIAS PRINCIPALES
// ===================================================================================================

// ============================================================================
// 📈 INTEGRACIÓN CON DATADOG (MONITOREO)
// ============================================================================

// Importar el tracer de Datadog para habilitar monitoreo APM
// La inicialización debe ocurrir antes de cargar Express para instrumentarlo
import tracer from 'dd-trace';

if (process.env.DATADOG_ENABLED === 'true') {
  tracer.init({
    service: process.env.DATADOG_SERVICE || 'jwt-example-backend',
    env: process.env.DATADOG_ENV || 'development',
    logInjection: true
  });
  tracer.use('express');
  console.log('📈 Datadog tracing habilitado');
}

// Framework Express.js para crear el servidor HTTP y manejar rutas REST
// Express es el framework web más popular para Node.js, proporciona routing, middleware y manejo de HTTP
import express from 'express';

// Librería jsonwebtoken - estándar de facto para JWT en Node.js
// Proporciona funciones para crear (sign), verificar (verify) y decodificar (decode) tokens JWT
// Soporta múltiples algoritmos: HS256, RS256, ES256, etc.
import jwt from 'jsonwebtoken';

// Middleware CORS (Cross-Origin Resource Sharing) para permitir peticiones desde diferentes dominios
// Esencial para permitir que el frontend (puerto 5173) se comunique con el backend (puerto 3000)
// Configura headers HTTP necesarios para superar las políticas de mismo origen del navegador
import cors from 'cors';

// ===================================================================================================
// 🔧 CONFIGURACIÓN BÁSICA DEL SERVIDOR
// ===================================================================================================

// Crear la instancia principal de la aplicación Express
// Esta instancia será el núcleo de nuestro servidor HTTP y manejará todas las rutas y middleware
const app = express();

// Puerto donde el servidor escuchará las conexiones HTTP
// En producción esto debería venir de process.env.PORT para flexibilidad de despliegue
const PORT = process.env.PORT || 3000;

// ===================================================================================================
// 🔑 CONFIGURACIÓN DE SEGURIDAD JWT
// ===================================================================================================

// SECRETOS JWT PARA FIRMADO DIGITAL DE TOKENS
// CRÍTICO: Estos secretos se obtienen de variables de entorno para máxima seguridad
// Los secretos deben ser strings aleatorios de al menos 256 bits (32 caracteres)
// En desarrollo se proporcionan valores por defecto para facilitar el setup

// Clave secreta para firmar y verificar ACCESS TOKENS
// Se usa con el algoritmo HMAC SHA-256 (HS256) para crear la firma digital
// Esta clave debe ser altamente secreta y rotarse periódicamente en producción
const JWT_SECRET = process.env.JWT_SECRET || 'development-jwt-secret-change-in-production';

// Clave separada para REFRESH TOKENS - implementa estrategia de doble-clave
// Usar claves separadas aumenta la seguridad: si una se compromete, la otra sigue siendo válida
// Permite invalidar solo un tipo de token sin afectar al otro
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'development-refresh-secret-change-in-production';

// ===================================================================================================
// ⚙️ CONFIGURACIÓN DE MIDDLEWARE DE EXPRESS
// ===================================================================================================

// Configurar middleware CORS para permitir comunicación cross-origin
// CORS es necesario porque el frontend (localhost:5173) y backend (localhost:3000) son diferentes orígenes
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173', // Dominio específico del frontend - más seguro que '*'
  credentials: true                // Permite envío de cookies y headers de autenticación
  // En producción: usar array de orígenes permitidos y configurar según el ambiente
}));

// Middleware para parsear automáticamente cuerpos JSON en las peticiones HTTP
// Convierte el JSON del body de las peticiones en objetos JavaScript accesibles via req.body
// Equivale a usar body-parser.json() en versiones anteriores de Express
app.use(express.json());

// ===================================================================================================
// 👥 SIMULACIÓN DE BASE DE DATOS DE USUARIOS
// ===================================================================================================

// Lista simulada de usuarios para demostración del sistema JWT
// IMPORTANTE: En producción esto debe ser una base de datos real (PostgreSQL, MongoDB, etc.)
// Las contraseñas deben estar hasheadas con bcrypt, Argon2 u otro algoritmo seguro
// NOTA: Estos son usuarios de ejemplo para demostración - cambiar en producción
const users = [
  { id: '1', username: 'quemasandy', password: '123123', role: 'user' },
  { id: '2', username: 'demo_admin', password: 'admin456', role: 'admin' },
  { id: '3', username: 'demo_super', password: 'super789', role: 'superadmin' },
  { id: '4', username: 'test_user', password: 'test123', role: 'user' }
];

// ===================================================================================================
// 🗄️ ALMACENAMIENTO TEMPORAL DE REFRESH TOKENS
// ===================================================================================================

// Array en memoria para almacenar refresh tokens válidos
// CRÍTICO: En producción usar Redis, base de datos o almacenamiento distribuido
// Este enfoque permite:
// 1. Invalidación inmediata de tokens (logout)
// 2. Revocación de tokens comprometidos
// 3. Límite de tokens activos por usuario
// 4. Auditoría de tokens emitidos
const refreshTokens: string[] = [];

// ===================================================================================================
// 🏷️ DEFINICIONES DE TIPOS TYPESCRIPT PARA JWT
// ===================================================================================================

// Interfaz para el payload del ACCESS TOKEN
// Define la estructura exacta de datos que se almacenan dentro del JWT
// Estos datos están VISIBLES (solo codificados en base64) pero FIRMADOS digitalmente
interface JwtPayload {
  userId: string;   // Identificador único del usuario - llave primaria de BD
  username: string; // Nombre de usuario - útil para logging y UI
  role: string;     // Rol de autorización - determina permisos y acceso a recursos
  iat?: number;     // "Issued At" - timestamp de emisión (añadido automáticamente por jwt.sign)
  exp?: number;     // "Expires" - timestamp de expiración (calculado desde expiresIn)
}

// Interfaz para el payload del REFRESH TOKEN
// Contiene datos mínimos necesarios para renovar access tokens
// Menos información = menor superficie de ataque si se compromete
interface RefreshTokenPayload {
  userId: string;      // Usuario propietario del token - para buscar en BD
  tokenVersion: number; // Versión del token - permite invalidar versiones antiguas
  iat?: number;        // Timestamp de emisión
  exp?: number;        // Timestamp de expiración (7 días)
}

// ===================================================================================================
// 🔐 FUNCIÓN PARA CREAR ACCESS TOKENS
// ===================================================================================================

// Genera un access token JWT de corta duración para un usuario autenticado
// Los access tokens contienen información del usuario y tienen vida corta (15 min)
// para minimizar el impacto si son comprometidos
function createAccessToken(user: typeof users[0]): string {
  console.log('🔐 =================================================');
  console.log('🍻 INICIANDO CREACIÓN DE ACCESS TOKEN');
  console.log('🔐 =================================================');
  
  // Construir el payload con información esencial del usuario
  // IMPORTANTE: No incluir información sensible como contraseñas
  const payload: JwtPayload = {
    userId: user.id,           // ID para consultas de BD
    username: user.username,   // Nombre para mostrar en UI
    role: user.role           // Rol para control de acceso
  };

  // Log detallado para debugging y auditoría
  console.log('📋 Payload a firmar:');
  console.log('   • User ID:', payload.userId);
  console.log('   • Username:', payload.username);
  console.log('   • Role:', payload.role);
  console.log('   • Algoritmo de firma: HS256 (HMAC SHA-256)');
  
  // Firmar digitalmente el payload usando la clave secreta
  // jwt.sign() hace tres cosas:
  // 1. Codifica header y payload en base64url
  // 2. Crea firma HMAC del header.payload usando la clave secreta
  // 3. Concatena: header.payload.signature
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: '15m' // Token de vida corta - balance entre seguridad y UX
  });
  
  // Información de depuración y confirmación
  console.log('✅ TOKEN FIRMADO EXITOSAMENTE:');
  console.log('   🔍 Longitud total:', token.length, 'caracteres');
  console.log('   🔍 Preview:', token.substring(0, 50) + '...');
  console.log('   ⏰ Duración: 15 minutos');
  console.log('   🛡️ Algoritmo: HS256');
  console.log('   📅 Creado:', new Date().toISOString());
  
  return token;
}

// ===================================================================================================
// 🔄 FUNCIÓN PARA CREAR REFRESH TOKENS
// ===================================================================================================

// Genera un refresh token JWT de larga duración para renovación de access tokens
// Los refresh tokens tienen vida larga (7 días) pero contienen menos información
// Se almacenan en el servidor para permitir revocación inmediata
function createRefreshToken(userId: string): string {
  console.log('🔄 =================================================');
  console.log('🔄 INICIANDO CREACIÓN DE REFRESH TOKEN');
  console.log('🔄 =================================================');
  
  // Payload minimalista para refresh token
  // Solo información esencial para renovar el access token
  const payload: RefreshTokenPayload = {
    userId,                  // Usuario propietario
    tokenVersion: 1         // Versión para invalidación masiva
  };

  console.log('📋 Payload del refresh token:');
  console.log('   • User ID:', payload.userId);
  console.log('   • Token Version:', payload.tokenVersion);
  console.log('   • Propósito: Renovación de access tokens');
  
  // Firmar con clave separada para mayor seguridad
  // Usar clave diferente permite rotación independiente y mejor aislamiento
  const token = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: '7d' // Vida larga para mejor UX - el usuario no necesita login frecuente
  });
  
  console.log('✅ REFRESH TOKEN CREADO:');
  console.log('   🔍 Longitud:', token.length, 'caracteres');
  console.log('   ⏰ Duración: 7 días');
  console.log('   🛡️ Algoritmo: HS256 (clave separada)');
  console.log('   📅 Creado:', new Date().toISOString());
  
  // CRÍTICO: Almacenar en lista de tokens válidos para control de revocación
  // Esto permite logout efectivo y revocación de tokens comprometidos
  refreshTokens.push(token);
  console.log('💾 Token agregado a lista válida (total activos:', refreshTokens.length, ')');
  
  return token;
}

// ===================================================================================================
// 🔒 MIDDLEWARE DE AUTENTICACIÓN JWT
// ===================================================================================================

// Middleware que intercepta peticiones para verificar access tokens JWT
// Se ejecuta ANTES de las rutas protegidas para validar autorización
// Implementa el patrón de autenticación Bearer Token estándar
const authenticateToken = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  console.log('\n🔒 ================================================');
  console.log('🔍 INICIANDO VERIFICACIÓN DE ACCESS TOKEN');
  console.log('🔒 ================================================');
  
  // PASO 1: Extraer token del header Authorization
  // El cliente debe enviar: Authorization: Bearer <jwt-token>
  const authHeader = req.headers['authorization'];
  
  console.log('📥 Analizando headers de autorización:');
  console.log('   • Authorization header presente:', !!authHeader);
  console.log('   • Valor completo:', authHeader || 'No presente');
  
  // Extraer solo el token (remover "Bearer " del inicio)
  // authHeader formato esperado: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log('🎫 Resultado de extracción:');
  console.log('   • Token extraído:', !!token);
  if (token) {
    console.log('   • Longitud del token:', token.length);
    console.log('   • Preview:', token.substring(0, 30) + '...');
  }

  // PASO 2: Validar presencia del token
  if (!token) {
    console.log('❌ FALLO DE AUTENTICACIÓN: Token no proporcionado');
    console.log('   • Causa: Header Authorization ausente o malformado');
    console.log('   • Formato esperado: "Authorization: Bearer <token>"');
    console.log('   • Respondiendo con status 401 Unauthorized');
    
    return res.status(401).json({
      error: 'Access token requerido',
      hint: 'Incluye header: Authorization: Bearer <token>',
      documentation: 'Consulta la documentación de autenticación JWT'
    });
  }

  // PASO 3: Verificar y decodificar el token
  try {
    console.log('🔓 Verificando token con clave secreta...');
    console.log('   • Algoritmo esperado: HS256');
    console.log('   • Verificando firma digital...');
    
    // jwt.verify() hace tres validaciones críticas:
    // 1. Decodifica y valida estructura del JWT
    // 2. Verifica firma usando la clave secreta
    // 3. Valida timestamps (nbf, exp, iat)
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    
    console.log('✅ TOKEN VERIFICADO EXITOSAMENTE:');
    console.log('   👤 Usuario:', decoded.username);
    console.log('   🆔 User ID:', decoded.userId);
    console.log('   🎭 Rol:', decoded.role);
    console.log('   📅 Emitido:', new Date(decoded.iat! * 1000).toLocaleString());
    console.log('   ⏰ Expira:', new Date(decoded.exp! * 1000).toLocaleString());
    
    // Calcular tiempo restante
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = decoded.exp! - now;
    console.log('   ⏱️ Tiempo restante:', timeLeft > 0 ? `${timeLeft} segundos` : 'EXPIRADO');
    
    // PASO 4: Adjuntar información del usuario al request
    // Esto permite a las rutas posteriores acceder a los datos del usuario autenticado
    (req as any).user = decoded;
    
    console.log('🚀 Continuando a la ruta protegida...');
    next(); // Pasar control al siguiente middleware/ruta
    
  } catch (error) {
    // MANEJO DETALLADO DE ERRORES JWT
    console.log('❌ ERROR DE VERIFICACIÓN JWT:');
    
    if (error instanceof jwt.TokenExpiredError) {
      // Token válido pero expirado - el cliente debe renovarlo
      console.log('⏰ TIPO: Token expirado');
      console.log('   • Fecha de expiración:', error.expiredAt);
      console.log('   • Tiempo transcurrido desde expiración:', 
                  Math.floor(Date.now() / 1000) - Math.floor(error.expiredAt.getTime() / 1000), 'segundos');
      console.log('   • Acción requerida: Cliente debe usar refresh token');
      
      return res.status(401).json({
        error: 'Token expirado',
        expiredAt: error.expiredAt,
        hint: 'Usa el refresh token para obtener uno nuevo',
        action: 'refresh_token'
      });
      
    } else if (error instanceof jwt.JsonWebTokenError) {
      // Token malformado, firma inválida, o algoritmo incorrecto
      console.log('🔍 TIPO: Token inválido');
      console.log('   • Detalle del error:', error.message);
      console.log('   • Posibles causas:');
      console.log('     - Firma digital inválida (token manipulado)');
      console.log('     - Algoritmo incorrecto');
      console.log('     - Token malformado o corrupto');
      console.log('     - Clave secreta incorrecta');
      
      return res.status(403).json({
        error: 'Token inválido',
        details: error.message,
        hint: 'Obtén un nuevo token a través del login'
      });
      
    } else {
      // Error inesperado del sistema
      console.log('💥 TIPO: Error inesperado del sistema');
      console.log('   • Error:', error);
      console.log('   • Acción: Revisar configuración del servidor');
      
      return res.status(500).json({ 
        error: 'Error interno verificando token',
        hint: 'Contacta al administrador del sistema'
      });
    }
  }
};

// ===================================================================================================
// 🌐 DEFINICIÓN DE RUTAS DE LA API
// ===================================================================================================

console.log('🚪 Configurando rutas de la API...');

// ===================================================================================================
// 🔐 RUTA: POST /api/login - Autenticación de usuarios
// ===================================================================================================

// Endpoint para autenticar usuarios y generar tokens JWT iniciales
// Esta es la puerta de entrada al sistema - genera ambos tokens (access + refresh)
app.post('/api/login', (req, res) => {
  console.log('\n🔐 ================================================');
  console.log('🔐 NUEVA SOLICITUD DE LOGIN JWT');
  console.log('🔐 ================================================');
  
  // Extraer credenciales del cuerpo de la petición
  const { username, password } = req.body;
  
  console.log('📥 Credenciales recibidas:');
  console.log('   • Username:', username || 'No proporcionado');
  console.log('   • Password:', password ? '[PRESENTE]' : 'No proporcionado');
  console.log('   • IP cliente:', req.ip);
  console.log('   • User-Agent:', req.get('User-Agent')?.substring(0, 50) + '...');
  
  // VALIDACIÓN BÁSICA DE ENTRADA
  if (!username || !password) {
    console.log('❌ VALIDACIÓN FALLÓ: Credenciales incompletas');
    return res.status(400).json({
      success: false,
      error: 'Username y password son requeridos',
      hint: 'Envía ambos campos en el body de la petición'
    });
  }
  
  console.log('🔍 Buscando usuario en base de datos simulada...');
  
  // BÚSQUEDA Y VERIFICACIÓN DE CREDENCIALES
  // En producción: usar bcrypt.compare() para verificar password hasheado
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    // ✅ CREDENCIALES VÁLIDAS - GENERAR TOKENS
    console.log('✅ AUTENTICACIÓN EXITOSA:');
    console.log('   👤 Usuario encontrado:');
    console.log('     - ID:', user.id);
    console.log('     - Username:', user.username);
    console.log('     - Rol:', user.role);
    console.log('   🎫 Generando tokens JWT...');
    
    // Crear ambos tokens para implementar estrategia de doble token
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user.id);
    
    console.log('\n📤 PREPARANDO RESPUESTA DE LOGIN EXITOSO:');
    console.log('   • Access token generado: ✅');
    console.log('   • Refresh token generado: ✅');
    console.log('   • Tokens almacenados en servidor: ✅');
    console.log('   • Enviando al cliente...');
    
    // Respuesta estructurada con toda la información necesaria
    res.json({
      success: true,
      message: 'Login exitoso - Bienvenido al sistema',
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role 
      },
      accessToken,                    // Token para peticiones API (15 min)
      refreshToken,                   // Token para renovación (7 días)
      tokenType: 'Bearer',           // Tipo estándar para JWT
      expiresIn: 900,                // 15 minutos en segundos
      note: '💡 Guarda ambos tokens para futuras peticiones',
      security: {
        algorithm: 'HS256',
        accessTokenDuration: '15 minutes',
        refreshTokenDuration: '7 days'
      }
    });
    
  } else {
    // ❌ CREDENCIALES INVÁLIDAS
    console.log('❌ AUTENTICACIÓN FALLÓ:');
    console.log('   • Usuario no encontrado o contraseña incorrecta');
    console.log('   • Username intentado:', username);
    console.log('   • Motivos posibles:');
    console.log('     - Usuario no existe');
    console.log('     - Contraseña incorrecta');
    console.log('     - Cuenta deshabilitada');
    console.log('   ⚠️ Respondiendo con error genérico por seguridad');
    
    // Respuesta genérica para no revelar si el usuario existe
    res.status(401).json({
      success: false,
      message: 'Credenciales incorrectas',
      hint: 'Verifica tu usuario y contraseña',
      security: 'Por seguridad, no se especifica qué credencial es incorrecta'
    });
  }
});

// ===================================================================================================
// 👤 RUTA: GET /api/profile - Perfil de usuario autenticado
// ===================================================================================================

// Ruta protegida que devuelve información del usuario autenticado
// Demuestra cómo extraer datos directamente del JWT sin consultar la base de datos
app.get('/api/profile', authenticateToken, (req, res) => {
  console.log('\n👤 ================================================');
  console.log('👤 SOLICITUD DE PERFIL DE USUARIO');
  console.log('👤 ================================================');
  
  // El middleware authenticateToken ya validó el token y agregó user al request
  const user = (req as any).user as JwtPayload;
  
  console.log('📋 Información extraída del JWT:');
  console.log('   👤 Usuario:', user.username);
  console.log('   🆔 ID:', user.userId);
  console.log('   🎭 Rol:', user.role);
  console.log('   📅 Token emitido:', new Date(user.iat! * 1000).toLocaleString());
  console.log('   ⏰ Token expira:', new Date(user.exp! * 1000).toLocaleString());
  
  // Calcular información adicional del token
  const now = Math.floor(Date.now() / 1000);
  const timeLeft = user.exp! - now;
  
  console.log('⏱️ Estado del token:');
  console.log('   • Tiempo restante:', timeLeft, 'segundos');
  console.log('   • Estado:', timeLeft > 0 ? 'VÁLIDO' : 'EXPIRADO');
  console.log('   • Porcentaje de vida restante:', Math.round((timeLeft / 900) * 100), '%');
  
  // Respuesta con información completa del perfil y metadata del token
  res.json({
    success: true,
    message: 'Perfil obtenido exitosamente',
    user: {
      id: user.userId,
      username: user.username,
      role: user.role
    },
    tokenInfo: {
      issuedAt: new Date(user.iat! * 1000).toISOString(),
      expiresAt: new Date(user.exp! * 1000).toISOString(),
      timeLeft: timeLeft + ' segundos',
      percentageLeft: Math.round((timeLeft / 900) * 100) + '%'
    },
    note: '🍻 Datos extraídos directamente del JWT - Sin consulta a BD',
    advantages: [
      'Sin latencia de base de datos',
      'Escalabilidad horizontal',
      'Stateless server architecture'
    ]
  });
});

// ===================================================================================================
// 🔒 RUTA: GET /api/secret-data - Datos protegidos basados en roles
// ===================================================================================================

// Ruta que demuestra autorización basada en roles usando información del JWT
// Diferentes usuarios obtienen diferentes datos según su rol
app.get('/api/secret-data', authenticateToken, (req, res) => {
  console.log('\n🔒 ================================================');
  console.log('🔒 ACCESO A DATOS SECRETOS (RBAC)');
  console.log('🔒 ================================================');
  
  const user = (req as any).user as JwtPayload;
  
  console.log('🎭 Análisis de autorización basada en roles:');
  console.log('   👤 Usuario:', user.username);
  console.log('   🏷️ Rol actual:', user.role);
  console.log('   🔍 Determinando nivel de acceso...');
  
  // IMPLEMENTACIÓN DE RBAC (Role-Based Access Control)
  let secretData: string;
  let accessLevel: string;
  let permissions: string[];
  
  switch (user.role) {
    case 'superadmin':
      secretData = '👑 Datos ultra secretos del super administrador';
      accessLevel = 'MÁXIMO';
      permissions = ['read', 'write', 'delete', 'admin', 'system'];
      console.log('   🔑 Nivel SUPERADMIN detectado - Acceso total concedido');
      break;
      
    case 'admin':
      secretData = '🔐 Datos secretos del administrador';
      accessLevel = 'ALTO';
      permissions = ['read', 'write', 'delete', 'admin'];
      console.log('   🔑 Nivel ADMIN detectado - Acceso administrativo concedido');
      break;
      
    default:
      secretData = '📊 Datos básicos del usuario';
      accessLevel = 'BÁSICO';
      permissions = ['read'];
      console.log('   🔑 Nivel USER detectado - Acceso básico concedido');
  }
  
  console.log('✅ Autorización completada:');
  console.log('   🎯 Nivel de acceso:', accessLevel);
  console.log('   🛡️ Permisos otorgados:', permissions.join(', '));
  console.log('   📦 Datos a retornar:', secretData.substring(0, 30) + '...');
  
  // Respuesta con datos personalizados según el rol
  res.json({
    success: true,
    message: `Datos secretos para usuario ${user.username}`,
    secretData,
    authorization: {
      userRole: user.role,
      accessLevel,
      permissions,
      grantedAt: new Date().toISOString()
    },
    user: {
      username: user.username,
      role: user.role
    },
    note: '🎭 Contenido personalizado basado en RBAC desde JWT',
    timestamp: new Date().toISOString()
  });
});

// ===================================================================================================
// 🔄 RUTA: POST /api/refresh - Renovación de access tokens
// ===================================================================================================

// Endpoint crítico para renovar access tokens usando refresh tokens válidos
// Implementa el patrón de renovación automática para mejorar UX sin comprometer seguridad
app.post('/api/refresh', (req, res) => {
  console.log('\n🔄 ================================================');
  console.log('🔄 SOLICITUD DE RENOVACIÓN DE ACCESS TOKEN');
  console.log('🔄 ================================================');
  
  const { refreshToken } = req.body;
  
  console.log('📥 Analizando petición de refresh:');
  console.log('   • Refresh token recibido:', !!refreshToken);
  if (refreshToken) {
    console.log('   • Longitud del token:', refreshToken.length);
    console.log('   • Preview:', refreshToken.substring(0, 30) + '...');
  }
  
  // VALIDACIÓN 1: Verificar presencia del refresh token
  if (!refreshToken) {
    console.log('❌ VALIDACIÓN FALLÓ: Refresh token no proporcionado');
    return res.status(401).json({
      error: 'Refresh token requerido',
      hint: 'Envía { "refreshToken": "tu-refresh-token" } en el body',
      format: 'application/json'
    });
  }
  
  // VALIDACIÓN 2: Verificar que el token esté en nuestra lista de tokens válidos
  console.log('🔍 Verificando token en lista de tokens válidos...');
  console.log('   • Tokens activos en servidor:', refreshTokens.length);
  
  if (!refreshTokens.includes(refreshToken)) {
    console.log('❌ VALIDACIÓN FALLÓ: Refresh token no encontrado en lista válida');
    console.log('   • Posibles causas:');
    console.log('     - Token ya fue usado y revocado');
    console.log('     - Token fue invalidado por logout');
    console.log('     - Token no fue emitido por este servidor');
    console.log('     - Ataque con token robado');
    
    return res.status(403).json({
      error: 'Refresh token inválido o revocado',
      hint: 'Realiza login para obtener nuevos tokens',
      security: 'Token no encontrado en lista de tokens válidos'
    });
  }
  
  console.log('✅ Token encontrado en lista válida');
  
  // VALIDACIÓN 3: Verificar firma y validez del refresh token
  try {
    console.log('🔓 Verificando firma del refresh token...');
    console.log('   • Algoritmo: HS256');
    console.log('   • Clave: Refresh secret key');
    
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as RefreshTokenPayload;
    
    console.log('✅ REFRESH TOKEN VERIFICADO:');
    console.log('   👤 User ID:', decoded.userId);
    console.log('   🔢 Token version:', decoded.tokenVersion);
    console.log('   📅 Emitido:', new Date(decoded.iat! * 1000).toLocaleString());
    console.log('   ⏰ Expira:', new Date(decoded.exp! * 1000).toLocaleString());
    
    // PASO 4: Buscar usuario correspondiente
    console.log('🔍 Buscando usuario en base de datos...');
    const user = users.find(u => u.id === decoded.userId);
    
    if (!user) {
      console.log('❌ ERROR: Usuario no encontrado');
      console.log('   • User ID buscado:', decoded.userId);
      console.log('   • Posibles causas:');
      console.log('     - Usuario fue eliminado');
      console.log('     - ID corrompido en token');
      console.log('     - Inconsistencia en base de datos');
      
      return res.status(404).json({ 
        error: 'Usuario no encontrado',
        hint: 'El usuario asociado al token no existe'
      });
    }
    
    console.log('✅ Usuario encontrado:', user.username);
    
    // PASO 5: Generar nuevo access token
    console.log('🏗️ Generando nuevo access token...');
    const newAccessToken = createAccessToken(user);
    
    console.log('🍻 RENOVACIÓN COMPLETADA EXITOSAMENTE:');
    console.log('   ✅ Nuevo access token generado');
    console.log('   ⏰ Válido por 15 minutos adicionales');
    console.log('   🔄 Refresh token permanece válido');
    console.log('   📤 Enviando respuesta al cliente...');
    
    // Respuesta con nuevo access token
    res.json({
      success: true,
      message: 'Access token renovado exitosamente',
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      expiresIn: 900,               // 15 minutos
      refreshInfo: {
        originalTokenStillValid: true,
        renewalsRemaining: 'Hasta que expire el refresh token',
        refreshTokenExpiresAt: new Date(decoded.exp! * 1000).toISOString()
      },
      note: '🔄 Token renovado automáticamente - UX mejorada sin comprometer seguridad'
    });
    
  } catch (error) {
    // MANEJO DE ERRORES EN VERIFICACIÓN DEL REFRESH TOKEN
    console.log('❌ ERROR VERIFICANDO REFRESH TOKEN:');
    
    if (error instanceof jwt.TokenExpiredError) {
      // Refresh token expirado - usuario debe hacer login completo
      console.log('⏰ TIPO: Refresh token expirado');
      console.log('   • Expiró en:', error.expiredAt);
      console.log('   • Acción: Limpiar de lista válida y requerir login');
      
      // Limpiar token expirado de la lista
      const index = refreshTokens.indexOf(refreshToken);
      if (index > -1) {
        refreshTokens.splice(index, 1);
        console.log('🗑️ Token expirado removido de lista válida');
      }
      
      return res.status(401).json({ 
        error: 'Refresh token expirado',
        hint: 'Realiza login nuevamente para obtener nuevos tokens',
        action: 'login_required',
        expiredAt: error.expiredAt
      });
      
    } else {
      // Error genérico de verificación
      console.log('💥 TIPO: Error de verificación genérico');
      console.log('   • Detalle:', error);
      console.log('   • Acción: Considerar token comprometido');
      
      return res.status(403).json({ 
        error: 'Refresh token inválido',
        hint: 'Token corrompido o manipulado - realiza login nuevamente'
      });
    }
  }
});

// ===================================================================================================
// 🚪 RUTA: POST /api/logout - Cerrar sesión e invalidar tokens
// ===================================================================================================

// Endpoint para cerrar sesión de forma segura invalidando el refresh token
// Implementa logout server-side para prevenir reutilización de tokens
app.post('/api/logout', (req, res) => {
  console.log('\n🚪 ================================================');
  console.log('🚪 SOLICITUD DE LOGOUT - INVALIDACIÓN DE SESIÓN');
  console.log('🚪 ================================================');
  
  const { refreshToken } = req.body;
  
  console.log('📥 Analizando solicitud de logout:');
  console.log('   • Refresh token para invalidar:', !!refreshToken);
  console.log('   • IP cliente:', req.ip);
  console.log('   • Tokens activos antes del logout:', refreshTokens.length);
  
  if (refreshToken) {
    console.log('🔍 Buscando refresh token en lista válida...');
    
    // Buscar y remover el refresh token de la lista de tokens válidos
    const index = refreshTokens.indexOf(refreshToken);
    
    if (index > -1) {
      // Token encontrado - proceder con invalidación
      refreshTokens.splice(index, 1);
      console.log('✅ INVALIDACIÓN EXITOSA:');
      console.log('   🗑️ Refresh token removido de lista válida');
      console.log('   📊 Tokens activos restantes:', refreshTokens.length);
      console.log('   🛡️ Token ya no puede ser usado para renovaciones');
    } else {
      console.log('⚠️ ADVERTENCIA: Token no encontrado en lista');
      console.log('   • Posibles razones:');
      console.log('     - Token ya fue invalidado previamente');
      console.log('     - Token nunca fue válido');
      console.log('     - Múltiples intentos de logout');
      console.log('   • Acción: Proceder con logout de todas formas');
    }
  } else {
    console.log('ℹ️ INFO: Logout sin refresh token');
    console.log('   • Cliente puede estar limpiando sesión local únicamente');
    console.log('   • No hay tokens del servidor para invalidar');
  }
  
  console.log('✅ LOGOUT COMPLETADO:');
  console.log('   🔓 Sesión del servidor invalidada');
  console.log('   💭 Access token seguirá válido hasta expiración natural');
  console.log('   🚫 Nuevas renovaciones bloqueadas');
  console.log('   📤 Confirmando logout al cliente...');
  
  // Confirmación de logout exitoso
  res.json({
    success: true,
    message: 'Logout exitoso - Sesión cerrada',
    serverAction: 'Refresh token invalidado en servidor',
    clientAction: 'Limpiar tokens del almacenamiento local',
    security: {
      refreshTokenInvalidated: !!refreshToken,
      accessTokenNote: 'El access token permanece técnicamente válido hasta su expiración natural (máx 15 min)',
      renewalBlocked: true
    },
    note: '💡 Por seguridad completa, también limpia los tokens del cliente',
    timestamp: new Date().toISOString()
  });
});

// ===================================================================================================
// 🔍 RUTA: POST /api/verify-token - Verificación manual de tokens (Debug)
// ===================================================================================================

// Endpoint de utilidad para verificar y analizar tokens JWT manualmente
// Útil para debugging, desarrollo y auditoría de tokens
app.post('/api/verify-token', (req, res) => {
  console.log('\n🔍 ================================================');
  console.log('🔍 VERIFICACIÓN MANUAL DE TOKEN (DEBUG)');
  console.log('🔍 ================================================');
  
  const { token } = req.body;
  
  console.log('📥 Token recibido para verificación:');
  console.log('   • Token presente:', !!token);
  if (token) {
    console.log('   • Longitud:', token.length);
    console.log('   • Estructura (partes):', token.split('.').length);
  }
  
  if (!token) {
    console.log('❌ Error: Token no proporcionado');
    return res.status(400).json({ 
      error: 'Token requerido para verificación',
      usage: 'Envía { "token": "tu-jwt-token" } en el body'
    });
  }
  
  try {
    console.log('🔍 PASO 1: Decodificación sin verificación...');
    // Decodificar sin verificar firma (para inspección)
    const decoded = jwt.decode(token, { complete: true });
    
    if (decoded) {
      console.log('✅ Token decodificado exitosamente:');
      console.log('   📋 Header:', JSON.stringify(decoded.header, null, 2));
      console.log('   📦 Payload:', JSON.stringify(decoded.payload, null, 2));
      console.log('   🔐 Signature presente:', !!decoded.signature);
    }
    
    console.log('🔍 PASO 2: Verificación con clave secreta...');
    // Verificar firma con clave secreta
    const verified = jwt.verify(token, JWT_SECRET) as JwtPayload;
    
    console.log('✅ TOKEN COMPLETAMENTE VÁLIDO:');
    console.log('   ✅ Estructura correcta');
    console.log('   ✅ Firma válida');
    console.log('   ✅ No expirado');
    console.log('   ✅ Algoritmo correcto');
    
    // Análisis temporal detallado
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = verified.exp! - now;
    const tokenAge = now - verified.iat!;
    
    console.log('📊 Análisis temporal:');
    console.log('   ⏰ Edad del token:', tokenAge, 'segundos');
    console.log('   ⏱️ Tiempo restante:', timeLeft, 'segundos');
    console.log('   📈 Porcentaje de vida usada:', Math.round((tokenAge / 900) * 100), '%');
    
    // Respuesta completa con análisis
    res.json({
      valid: true,
      message: 'Token verificado exitosamente',
      tokenAnalysis: {
        structure: 'Válida (3 partes)',
        signature: 'Válida',
        algorithm: decoded?.header?.alg || 'Unknown',
        expiration: 'No expirado'
      },
      decoded: verified,
      header: decoded?.header,
      payload: decoded?.payload,
      temporal: {
        issuedAt: new Date(verified.iat! * 1000).toISOString(),
        expiresAt: new Date(verified.exp! * 1000).toISOString(),
        ageInSeconds: tokenAge,
        timeLeftInSeconds: timeLeft,
        percentageUsed: Math.round((tokenAge / 900) * 100)
      },
      security: {
        signatureVerified: true,
        algorithmSecure: decoded?.header?.alg === 'HS256',
        notExpired: timeLeft > 0
      }
    });
    
  } catch (error) {
    console.log('❌ ERROR EN VERIFICACIÓN:');
    console.log('   • Tipo de error:', error instanceof Error ? error.constructor.name : 'Unknown');
    console.log('   • Mensaje:', error instanceof Error ? error.message : 'Error desconocido');
    
    // Intentar decodificar sin verificar para dar más información
    try {
      const decoded = jwt.decode(token, { complete: true });
      console.log('ℹ️ Información del token (sin verificar firma):');
      console.log('   📋 Header:', decoded?.header);
      console.log('   📦 Payload:', decoded?.payload);
      
      res.status(401).json({
        valid: false,
        error: error instanceof Error ? error.message : 'Token inválido',
        tokenStructure: decoded ? 'Válida' : 'Inválida',
        possibleCauses: [
          'Token expirado',
          'Firma inválida (token manipulado)',
          'Algoritmo incorrecto',
          'Clave secreta incorrecta',
          'Token malformado'
        ],
        decoded: decoded?.payload || null,
        header: decoded?.header || null,
        hint: 'Obtén un nuevo token através del login'
      });
    } catch {
      console.log('💥 Token completamente malformado');
      res.status(400).json({
        valid: false,
        error: 'Token completamente malformado',
        structure: 'Inválida',
        hint: 'Verifica que el token tenga el formato correcto: header.payload.signature'
      });
    }
  }
});

// ===================================================================================================
// 📊 RUTA: GET /api/status - Estado del servidor y estadísticas
// ===================================================================================================

// Endpoint informativo que muestra el estado del servidor y estadísticas de JWT
app.get('/api/status', (req, res) => {
  console.log('\n📊 ================================================');
  console.log('📊 CONSULTA DE ESTADO DEL SERVIDOR');
  console.log('📊 ================================================');
  
  console.log('📈 Recopilando estadísticas del servidor:');
  console.log('   🔄 Refresh tokens activos:', refreshTokens.length);
  console.log('   👥 Usuarios registrados:', users.length);
  console.log('   🕐 Uptime del proceso:', process.uptime(), 'segundos');
  console.log('   💾 Uso de memoria:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  
  // Análisis de tokens activos
  let tokenStats = {
    total: refreshTokens.length,
    oldestToken: null as Date | null,
    newestToken: null as Date | null
  };
  
  // Analizar tokens para estadísticas temporales
  if (refreshTokens.length > 0) {
    console.log('🔍 Analizando tokens activos...');
    try {
      const tokenDates = refreshTokens.map(token => {
        const decoded = jwt.decode(token) as any;
        return new Date(decoded.iat * 1000);
      }).sort();
      
      tokenStats.oldestToken = tokenDates[0];
      tokenStats.newestToken = tokenDates[tokenDates.length - 1];
      
      console.log('   📅 Token más antiguo:', tokenStats.oldestToken?.toISOString());
      console.log('   📅 Token más reciente:', tokenStats.newestToken?.toISOString());
    } catch (error) {
      console.log('   ⚠️ Error analizando tokens:', error);
    }
  }
  
  // Respuesta completa con estado del servidor
  res.json({
    server: 'JWT Authentication Server',
    status: 'running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    
    // Estadísticas de JWT
    jwtStatistics: {
      activeRefreshTokens: refreshTokens.length,
      registeredUsers: users.length,
      tokenStats
    },
    
    // Configuración JWT
    jwtConfiguration: {
      accessTokenExpiry: '15 minutes',
      refreshTokenExpiry: '7 days',
      algorithm: 'HS256',
      dualTokenStrategy: true,
      serverSideRevocation: true
    },
    
    // Endpoints disponibles
    endpoints: {
      authentication: [
        'POST /api/login',
        'POST /api/logout',
        'POST /api/refresh'
      ],
      protected: [
        'GET /api/profile',
        'GET /api/secret-data'
      ],
      utility: [
        'POST /api/verify-token',
        'GET /api/status'
      ]
    },
    
    // Información del sistema
    system: {
      nodeVersion: process.version,
      platform: process.platform,
      uptime: Math.round(process.uptime()),
      memoryUsage: {
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        external: Math.round(process.memoryUsage().external / 1024 / 1024)
      }
    },
    
    // Características de seguridad
    security: {
      cors: 'Configurado para frontend específico',
      tokenStorage: 'En memoria (usar Redis en producción)',
      secretManagement: 'Hardcoded (usar variables de entorno en producción)',
      passwordHashing: 'No implementado (usar bcrypt en producción)',
      httpsRequired: 'Recomendado para producción'
    }
  });
});

// ===================================================================================================
// 🚀 INICIALIZACIÓN DEL SERVIDOR
// ===================================================================================================

// Iniciar el servidor HTTP y comenzar a escuchar peticiones
app.listen(PORT, () => {
  console.log('\n🚀 ================================================');
  console.log('🚀 JWT AUTHENTICATION SERVER INICIADO');
  console.log('🚀 ================================================');
  console.log(`📱 Puerto: ${PORT}`);
  console.log(`🌐 URL base: http://localhost:${PORT}`);
  console.log('🔐 JWT authentication configured');
  console.log('🔄 Refresh token system enabled');
  console.log('💡 Endpoints disponibles en http://localhost:3000/api/');
  console.log('\n📋 CONFIGURACIÓN DEL SERVIDOR:');
  console.log('   ✅ Express.js configurado');
  console.log('   ✅ CORS habilitado para frontend');
  console.log('   ✅ Middleware JSON configurado');
  console.log('   ✅ Autenticación JWT implementada');
  console.log('   ✅ Rutas protegidas configuradas');
  console.log('   ✅ Sistema de refresh tokens activo');
  console.log('\n🔒 CARACTERÍSTICAS DE SEGURIDAD:');
  console.log('   🛡️ Estrategia de doble token (access + refresh)');
  console.log('   🛡️ Verificación de firma digital');
  console.log('   🛡️ Expiración automática de tokens');
  console.log('   🛡️ Revocación server-side de refresh tokens');
  console.log('   🛡️ Control de acceso basado en roles (RBAC)');
  console.log('\n⚠️ NOTAS PARA PRODUCCIÓN:');
  console.log('   🔧 Usar variables de entorno para secretos');
  console.log('   🔧 Implementar Redis para storage de tokens');
  console.log('   🔧 Usar bcrypt para hashing de contraseñas');
  console.log('   🔧 Configurar HTTPS obligatorio');
  console.log('   🔧 Implementar rate limiting');
  console.log('   🔧 Agregar logging y monitoreo');
  console.log('\n🎯 SERVIDOR LISTO PARA RECIBIR PETICIONES');
  console.log('🎯 ================================================\n');
});