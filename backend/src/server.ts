// Importamos Express para crear el servidor HTTP
import express from 'express';
// Librería jsonwebtoken para firmar y verificar tokens
import jwt from 'jsonwebtoken';
// Middleware CORS para permitir peticiones desde el frontend
import cors from 'cors';

// Creamos la aplicación de Express
const app = express();
// Puerto donde escuchará el servidor
const PORT = 3000;

// 🔑 Secretos JWT (en producción usar variables de entorno)
// Clave secreta utilizada para firmar los access tokens
const JWT_SECRET = 'mi-super-secreto-jwt-para-firmar-tokens';
// Clave separada para firmar los refresh tokens
const JWT_REFRESH_SECRET = 'mi-secreto-para-refresh-tokens';

// Configuración de middlewares
// Habilitamos CORS para que el frontend pueda comunicarse con la API
app.use(cors({
  origin: 'http://localhost:5173', // Dominio permitido
  credentials: true               // Enviar cookies si fuese necesario
}));

// Interpretar cuerpos JSON automáticamente
app.use(express.json());

// 📊 Usuarios simulados
// Lista simulada de usuarios para el ejemplo
const users = [
  { id: '1', username: 'juan', password: '12345', role: 'user' },
  { id: '2', username: 'maria', password: 'password', role: 'admin' },
  { id: '3', username: 'admin', password: 'admin123', role: 'superadmin' }
];

// 💄 Storage simple para refresh tokens (en producción usar Redis/DB)
// Aquí almacenaremos de forma temporal los refresh tokens válidos
const refreshTokens: string[] = [];

// 🏷️ Tipos TypeScript para JWT
// Definimos la estructura que tendrán los datos dentro del access token
interface JwtPayload {
  userId: string;   // Identificador único del usuario
  username: string; // Nombre de usuario
  role: string;     // Rol asignado
  iat?: number;     // Fecha de emisión (opcional)
  exp?: number;     // Fecha de expiración (opcional)
}

// Datos que incluimos dentro del refresh token
interface RefreshTokenPayload {
  userId: string;      // Usuario al que pertenece
  tokenVersion: number; // Para invalidar tokens antiguos
  iat?: number;
  exp?: number;
}

// 🔐 Función para crear Access Token
// Genera un access token corto para un usuario
function createAccessToken(user: typeof users[0]): string {
  // Información que codificaremos dentro del JWT
  const payload: JwtPayload = {
    userId: user.id,
    username: user.username,
    role: user.role
  };

  // Mostramos en consola el payload que será firmado
  console.log('🍻 CREANDO ACCESS TOKEN:');
  console.log('📋 Payload:', JSON.stringify(payload, null, 2));
  
  // Firmamos el token con nuestra clave secreta
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: '15m' // Token de acceso corto
  });
  
  // Imprimimos parte del token y la expiración para depurar
  console.log('🔐 Token firmado (primeros 50 chars):', token.substring(0, 50) + '...');
  console.log('⏰ Expira en: 15 minutos');
  
  // Devolvemos el JWT ya firmado
  return token;
}

// 🔄 Función para crear Refresh Token
// Genera un refresh token de larga duración
function createRefreshToken(userId: string): string {
  // Datos mínimos que guardaremos en el refresh token
  const payload: RefreshTokenPayload = {
    userId,
    tokenVersion: 1 // Versión para invalidar tokens
  };

  // Mostrar el payload por consola para depuración
  console.log('🔄 CREANDO REFRESH TOKEN:');
  console.log('📋 Payload:', JSON.stringify(payload, null, 2));
  
  // Firmamos el refresh token con su clave específica
  const token = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: '7d' // Refresh token largo
  });
  
  // Mensajes informativos en consola
  console.log('🔐 Refresh token creado');
  console.log('⏰ Expira en: 7 días');
  
  // Guardar en nuestra "base de datos" de refresh tokens
  refreshTokens.push(token);
  
  // Devolvemos el refresh token generado
  return token;
}

// 🔒 Middleware para verificar Access Token
// Middleware que comprueba el access token enviado por el cliente
const authenticateToken = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  console.log('\n🔍 VERIFICANDO ACCESS TOKEN...');
  
  // Extraemos el token del encabezado Authorization
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"
  
  console.log('📥 Authorization header:', authHeader || 'No presente');
  console.log('🍻 Token extraído:', token ? token.substring(0, 50) + '...' : 'No encontrado');

  if (!token) {
    console.log('❌ No se encontró token en Authorization header');
    return res.status(401).json({
      error: 'Access token requerido',
      hint: 'Incluye: Authorization: Bearer <token>'
    });
  }

  try {
    console.log('🔓 Verificando token con secret...');
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    
    console.log('✅ TOKEN VÁLIDO:');
    console.log('📋 Datos decodificados:', JSON.stringify(decoded, null, 2));
    console.log('⏰ Expira en:', new Date(decoded.exp! * 1000).toISOString());
    
    // Agregar información del usuario al request
    // Guardamos la info del usuario en la petición para usarla en las rutas
    (req as any).user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      // El token caducó: indicamos al cliente que debe renovarlo
      console.log('⏰ TOKEN EXPIRADO');
      console.log('📅 Expiró en:', error.expiredAt);
      return res.status(401).json({
        error: 'Token expirado',
        expiredAt: error.expiredAt,
        hint: 'Usa el refresh token para obtener uno nuevo'
      });
    } else if (error instanceof jwt.JsonWebTokenError) {
      // Token mal formado o con firma inválida
      console.log('❌ TOKEN INVÁLIDO:', error.message);
      return res.status(403).json({
        error: 'Token inválido',
        details: error.message
      });
    } else {
      // Cualquier otro error inesperado
      console.log('💥 ERROR INESPERADO:', error);
      return res.status(500).json({ error: 'Error verificando token' });
    }
  }
};

// 🚪 RUTAS

// Endpoint para autenticarse y obtener los tokens iniciales
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('\n🔐 INTENTO DE LOGIN JWT:');
  console.log('👤 Usuario:', username);
  console.log('🗑 Password:', password ? '***' : 'No enviado');
  
  // Buscamos el usuario en nuestra lista
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    console.log('✅ CREDENCIALES VÁLIDAS');
    console.log('👤 Usuario encontrado:', { id: user.id, username: user.username, role: user.role });
    
    // Credenciales válidas: generamos los dos tokens
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user.id);
    
    console.log('\n📤 ENVIANDO RESPUESTA CON TOKENS...');
    
    // Devolvemos al cliente los tokens para que los guarde
    res.json({
      success: true,
      message: 'Login exitoso',
      user: { id: user.id, username: user.username, role: user.role },
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 900, // 15 minutos en segundos
      note: '💡 Guarda estos tokens para futuras peticiones'
    });
  } else {
    // Credenciales incorrectas
    console.log('❌ CREDENCIALES INVÁLIDAS');
    res.status(401).json({
      success: false,
      message: 'Usuario o contraseña incorrectos'
    });
  }
});

// Ruta protegida que devuelve el perfil del usuario autenticado
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  // Información de depuración
  console.log('\n👤 ACCESO A PERFIL:');
  console.log('✅ Usuario autenticado:', user.username);
  console.log('🎝️ Rol:', user.role);
  
  // Respondemos con la información extraída del token
  res.json({
    success: true,
    user: {
      id: user.userId,
      username: user.username,
      role: user.role
    },
    tokenInfo: {
      issuedAt: new Date(user.iat! * 1000).toISOString(),
      expiresAt: new Date(user.exp! * 1000).toISOString(),
      timeLeft: user.exp! - Math.floor(Date.now() / 1000) + ' segundos'
    },
    note: '🍻 Datos extraídos directamente del JWT'
  });
});

// Datos protegidos (requiere autenticación)
// Ruta protegida que devuelve información dependiendo del rol del usuario
app.get('/api/secret-data', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  // Registro en consola de la solicitud
  console.log('\n🔒 ACCESO A DATOS SECRETOS:');
  console.log('👤 Usuario:', user.username);
  console.log('🎝️ Rol:', user.role);
  
  // Datos diferentes según el rol
  let secretData;
  switch (user.role) {
    case 'superadmin':
      // El rol más alto obtiene información muy sensible
      secretData = '👑 Datos ultra secretos del super admin';
      break;
    case 'admin':
      // Información solo para administradores
      secretData = '🔐 Datos secretos del admin';
      break;
    default:
      // Para usuarios normales devolvemos datos genéricos
      secretData = '📊 Datos básicos del usuario';
  }
  
  // Enviamos la información personalizada al cliente
  res.json({
    success: true,
    secretData,
    userRole: user.role,
    message: `¡Hola ${user.username}! Estos son tus datos según tu rol.`,
    timestamp: new Date().toISOString()
  });
});

// Endpoint para obtener un nuevo access token usando un refresh token válido
app.post('/api/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n🔄 REFRESH TOKEN REQUEST:');
  console.log('🍻 Refresh token recibido:', refreshToken ? '¡Sí!' : 'No');
  
  if (!refreshToken) {
    // El cliente no envió el token necesario
    console.log('❌ No se envió refresh token');
    return res.status(401).json({
      error: 'Refresh token requerido',
      hint: 'Envía { "refreshToken": "tu-refresh-token" }'
    });
  }
  
  // Verificar que el refresh token esté en nuestra lista
  if (!refreshTokens.includes(refreshToken)) {
    console.log('❌ Refresh token no encontrado en la lista válida');
    return res.status(403).json({
      error: 'Refresh token inválido o revocado'
    });
  }
  
  try {
    // Validamos que el refresh token sea auténtico
    console.log('🔓 Verificando refresh token...');
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as RefreshTokenPayload;
    
    console.log('✅ REFRESH TOKEN VÁLIDO:');
    console.log('👤 User ID:', decoded.userId);
    console.log('🟢 Token version:', decoded.tokenVersion);
    
    // Buscar usuario
    // Buscamos al usuario correspondiente en la base simulada
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      console.log('❌ Usuario no encontrado');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Crear nuevo access token
    // Generamos un nuevo access token reutilizando los datos del usuario
    const newAccessToken = createAccessToken(user);
    
    console.log('🍻 NUEVO ACCESS TOKEN GENERADO');
    
    // Enviamos el nuevo token al cliente
    res.json({
      success: true,
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      expiresIn: 900, // 15 minutos
      message: 'Access token renovado exitosamente'
    });
    
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      // El refresh token ya expiró, lo eliminamos de la lista
      console.log('⏰ REFRESH TOKEN EXPIRADO');
      const index = refreshTokens.indexOf(refreshToken);
      if (index > -1) refreshTokens.splice(index, 1);
      
      return res.status(401).json({ 
        error: 'Refresh token expirado',
        hint: 'Debes hacer login nuevamente'
      });
    } else {
      // Error genérico de verificación
      console.log('❌ ERROR VERIFICANDO REFRESH TOKEN:', error);
      return res.status(403).json({ error: 'Refresh token inválido' });
    }
  }
});

// Logout (invalidar refresh token)
// Endpoint para cerrar sesión e invalidar el refresh token
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n🚪 LOGOUT REQUEST:');
  console.log('🍻 Refresh token para invalidar:', refreshToken ? 'Recibido' : 'No enviado');
  
  if (refreshToken) {
    // Si recibimos un refresh token, lo eliminamos de la lista válida
    const index = refreshTokens.indexOf(refreshToken);
    if (index > -1) {
      refreshTokens.splice(index, 1);
      console.log('🗑 Refresh token removido de la lista válida');
    }
  }
  
  console.log('✅ LOGOUT COMPLETADO');
  
  // Respondemos confirmando que se invalidó el refresh token
  res.json({
    success: true,
    message: 'Logout exitoso',
    note: '💡 El access token seguirá válido hasta que expire (15 min)'
  });
});

// Verificar token (útil para debugging)
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  
  console.log('\n🔍 VERIFICACIÓN MANUAL DE TOKEN:');
  
  if (!token) {
    return res.status(400).json({ error: 'Token requerido' });
  }
  
  try {
    // Decodificar sin verificar (para ver contenido)
    const decoded = jwt.decode(token, { complete: true });
    console.log('📋 Token decodificado (sin verificar):', JSON.stringify(decoded, null, 2));
    
    // Verificar con secret
    const verified = jwt.verify(token, JWT_SECRET) as JwtPayload;
    console.log('✅ Token verificado exitosamente');
    
    res.json({
      valid: true,
      decoded: verified,
      header: decoded?.header,
      payload: decoded?.payload,
      isExpired: false,
      expiresAt: new Date(verified.exp! * 1000).toISOString()
    });
    
  } catch (error) {
    console.log('❌ Token inválido:', error);
    
    // Intentar decodificar sin verificar para mostrar contenido
    try {
      const decoded = jwt.decode(token, { complete: true });
      res.status(401).json({
        valid: false,
        error: error instanceof Error ? error.message : 'Token inválido',
        decoded: decoded?.payload,
        header: decoded?.header
      });
    } catch {
      res.status(400).json({
        valid: false,
        error: 'Token malformado'
      });
    }
  }
});

// Estado del servidor
app.get('/api/status', (req, res) => {
  console.log('\n📊 ESTADO DEL SERVIDOR:');
  console.log('🔄 Refresh tokens activos:', refreshTokens.length);
  
  res.json({
    server: 'JWT Auth Server',
    status: 'running',
    activeRefreshTokens: refreshTokens.length,
    jwtConfig: {
      accessTokenExpiry: '15 minutes',
      refreshTokenExpiry: '7 days',
      algorithm: 'HS256'
    },
    endpoints: [
      'POST /api/login',
      'GET /api/profile',
      'GET /api/secret-data',
      'POST /api/refresh',
      'POST /api/logout',
      'POST /api/verify-token'
    ]
  });
});

app.listen(PORT, () => {
  console.log('🚀 JWT AUTH SERVER INICIADO');
  console.log(`📱 Puerto: ${PORT}`);
  console.log(`🔐 JWT Secret configurado: ${JWT_SECRET.substring(0, 20)}...`);
  console.log(`🔄 Refresh Secret configurado: ${JWT_REFRESH_SECRET.substring(0, 20)}...`);
  console.log('💡 Endpoints disponibles en http://localhost:3000/api/');
});
