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

// \ud83d\udd11 Secretos JWT (en producci\u00f3n usar variables de entorno)
// Clave secreta utilizada para firmar los access tokens
const JWT_SECRET = 'mi-super-secreto-jwt-para-firmar-tokens';
// Clave separada para firmar los refresh tokens
const JWT_REFRESH_SECRET = 'mi-secreto-para-refresh-tokens';

// Configuraci\u00f3n de middlewares
// Habilitamos CORS para que el frontend pueda comunicarse con la API
app.use(cors({
  origin: 'http://localhost:5173', // Dominio permitido
  credentials: true               // Enviar cookies si fuese necesario
}));

// Interpretar cuerpos JSON automáticamente
app.use(express.json());

// \ud83d\udcca Usuarios simulados
// Lista simulada de usuarios para el ejemplo
const users = [
  { id: '1', username: 'juan', password: '123456', role: 'user' },
  { id: '2', username: 'maria', password: 'password', role: 'admin' },
  { id: '3', username: 'admin', password: 'admin123', role: 'superadmin' }
];

// \ud83d\udc84 Storage simple para refresh tokens (en producci\u00f3n usar Redis/DB)
// Aquí almacenaremos de forma temporal los refresh tokens válidos
const refreshTokens: string[] = [];

// \ud83c\udff7\ufe0f Tipos TypeScript para JWT
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

// \ud83d\udd10 Funci\u00f3n para crear Access Token
// Genera un access token corto para un usuario
function createAccessToken(user: typeof users[0]): string {
  // Información que codificaremos dentro del JWT
  const payload: JwtPayload = {
    userId: user.id,
    username: user.username,
    role: user.role
  };

  // Mostramos en consola el payload que será firmado
  console.log('\ud83c\udf7b CREANDO ACCESS TOKEN:');
  console.log('\ud83d\udccb Payload:', JSON.stringify(payload, null, 2));
  
  // Firmamos el token con nuestra clave secreta
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: '15m' // Token de acceso corto
  });
  
  // Imprimimos parte del token y la expiración para depurar
  console.log('\ud83d\udd10 Token firmado (primeros 50 chars):', token.substring(0, 50) + '...');
  console.log('\u23f0 Expira en: 15 minutos');
  
  // Devolvemos el JWT ya firmado
  return token;
}

// \ud83d\udd04 Funci\u00f3n para crear Refresh Token
// Genera un refresh token de larga duración
function createRefreshToken(userId: string): string {
  // Datos mínimos que guardaremos en el refresh token
  const payload: RefreshTokenPayload = {
    userId,
    tokenVersion: 1 // Versi\u00f3n para invalidar tokens
  };

  // Mostrar el payload por consola para depuración
  console.log('\ud83d\udd04 CREANDO REFRESH TOKEN:');
  console.log('\ud83d\udccb Payload:', JSON.stringify(payload, null, 2));
  
  // Firmamos el refresh token con su clave específica
  const token = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: '7d' // Refresh token largo
  });
  
  // Mensajes informativos en consola
  console.log('\ud83d\udd10 Refresh token creado');
  console.log('\u23f0 Expira en: 7 d\u00edas');
  
  // Guardar en nuestra "base de datos" de refresh tokens
  refreshTokens.push(token);
  
  // Devolvemos el refresh token generado
  return token;
}

// \ud83d\udd12 Middleware para verificar Access Token
// Middleware que comprueba el access token enviado por el cliente
const authenticateToken = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  console.log('\n\ud83d\udd0d VERIFICANDO ACCESS TOKEN...');
  
  // Extraemos el token del encabezado Authorization
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"
  
  console.log('\ud83d\udce5 Authorization header:', authHeader || 'No presente');
  console.log('\ud83c\udf7b Token extra\u00eddo:', token ? token.substring(0, 50) + '...' : 'No encontrado');

  if (!token) {
    console.log('\u274c No se encontr\u00f3 token en Authorization header');
    return res.status(401).json({
      error: 'Access token requerido',
      hint: 'Incluye: Authorization: Bearer <token>'
    });
  }

  try {
    console.log('\ud83d\udd13 Verificando token con secret...');
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    
    console.log('\u2705 TOKEN V\u00c1LIDO:');
    console.log('\ud83d\udccb Datos decodificados:', JSON.stringify(decoded, null, 2));
    console.log('\u23f0 Expira en:', new Date(decoded.exp! * 1000).toISOString());
    
    // Agregar informaci\u00f3n del usuario al request
    // Guardamos la info del usuario en la petición para usarla en las rutas
    (req as any).user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      // El token caducó: indicamos al cliente que debe renovarlo
      console.log('\u23f0 TOKEN EXPIRADO');
      console.log('\ud83d\udcc5 Expir\u00f3 en:', error.expiredAt);
      return res.status(401).json({
        error: 'Token expirado',
        expiredAt: error.expiredAt,
        hint: 'Usa el refresh token para obtener uno nuevo'
      });
    } else if (error instanceof jwt.JsonWebTokenError) {
      // Token mal formado o con firma inválida
      console.log('\u274c TOKEN INV\u00c1LIDO:', error.message);
      return res.status(403).json({
        error: 'Token inv\u00e1lido',
        details: error.message
      });
    } else {
      // Cualquier otro error inesperado
      console.log('\ud83d\udca5 ERROR INESPERADO:', error);
      return res.status(500).json({ error: 'Error verificando token' });
    }
  }
};

// \ud83d\udeaa RUTAS

// Endpoint para autenticarse y obtener los tokens iniciales
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('\n\ud83d\udd10 INTENTO DE LOGIN JWT:');
  console.log('\ud83d\udc64 Usuario:', username);
  console.log('\ud83d\uddd1 Password:', password ? '***' : 'No enviado');
  
  // Buscamos el usuario en nuestra lista
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    console.log('\u2705 CREDENCIALES V\u00c1LIDAS');
    console.log('\ud83d\udc64 Usuario encontrado:', { id: user.id, username: user.username, role: user.role });
    
    // Credenciales válidas: generamos los dos tokens
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user.id);
    
    console.log('\n\ud83d\udce4 ENVIANDO RESPUESTA CON TOKENS...');
    
    // Devolvemos al cliente los tokens para que los guarde
    res.json({
      success: true,
      message: 'Login exitoso',
      user: { id: user.id, username: user.username, role: user.role },
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 900, // 15 minutos en segundos
      note: '\ud83d\udca1 Guarda estos tokens para futuras peticiones'
    });
  } else {
    // Credenciales incorrectas
    console.log('\u274c CREDENCIALES INV\u00c1LIDAS');
    res.status(401).json({
      success: false,
      message: 'Usuario o contrase\u00f1a incorrectos'
    });
  }
});

// Ruta protegida que devuelve el perfil del usuario autenticado
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  // Información de depuración
  console.log('\n\ud83d\udc64 ACCESO A PERFIL:');
  console.log('\u2705 Usuario autenticado:', user.username);
  console.log('\ud83c\udf9d\ufe0f Rol:', user.role);
  
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
    note: '\ud83c\udf7b Datos extra\u00eddos directamente del JWT'
  });
});

// Datos protegidos (requiere autenticaci\u00f3n)
// Ruta protegida que devuelve información dependiendo del rol del usuario
app.get('/api/secret-data', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  // Registro en consola de la solicitud
  console.log('\n\ud83d\udd12 ACCESO A DATOS SECRETOS:');
  console.log('\ud83d\udc64 Usuario:', user.username);
  console.log('\ud83c\udf9d\ufe0f Rol:', user.role);
  
  // Datos diferentes según el rol
  let secretData;
  switch (user.role) {
    case 'superadmin':
      // El rol más alto obtiene información muy sensible
      secretData = '\ud83d\udc51 Datos ultra secretos del super admin';
      break;
    case 'admin':
      // Información solo para administradores
      secretData = '\ud83d\udd10 Datos secretos del admin';
      break;
    default:
      // Para usuarios normales devolvemos datos genéricos
      secretData = '\ud83d\udcca Datos b\u00e1sicos del usuario';
  }
  
  // Enviamos la información personalizada al cliente
  res.json({
    success: true,
    secretData,
    userRole: user.role,
    message: `\u00a1Hola ${user.username}! Estos son tus datos seg\u00fan tu rol.`,
    timestamp: new Date().toISOString()
  });
});

// Endpoint para obtener un nuevo access token usando un refresh token válido
app.post('/api/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n\ud83d\udd04 REFRESH TOKEN REQUEST:');
  console.log('\ud83c\udf7b Refresh token recibido:', refreshToken ? '\u00a1S\u00ed!' : 'No');
  
  if (!refreshToken) {
    // El cliente no envió el token necesario
    console.log('\u274c No se envi\u00f3 refresh token');
    return res.status(401).json({
      error: 'Refresh token requerido',
      hint: 'Env\u00eda { "refreshToken": "tu-refresh-token" }'
    });
  }
  
  // Verificar que el refresh token esté en nuestra lista
  if (!refreshTokens.includes(refreshToken)) {
    console.log('\u274c Refresh token no encontrado en la lista v\u00e1lida');
    return res.status(403).json({
      error: 'Refresh token inv\u00e1lido o revocado'
    });
  }
  
  try {
    // Validamos que el refresh token sea auténtico
    console.log('\ud83d\udd13 Verificando refresh token...');
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as RefreshTokenPayload;
    
    console.log('\u2705 REFRESH TOKEN V\u00c1LIDO:');
    console.log('\ud83d\udc64 User ID:', decoded.userId);
    console.log('\ud83d\udfe2 Token version:', decoded.tokenVersion);
    
    // Buscar usuario
    // Buscamos al usuario correspondiente en la base simulada
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      console.log('\u274c Usuario no encontrado');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Crear nuevo access token
    // Generamos un nuevo access token reutilizando los datos del usuario
    const newAccessToken = createAccessToken(user);
    
    console.log('\ud83c\udf7b NUEVO ACCESS TOKEN GENERADO');
    
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
      console.log('\u23f0 REFRESH TOKEN EXPIRADO');
      const index = refreshTokens.indexOf(refreshToken);
      if (index > -1) refreshTokens.splice(index, 1);
      
      return res.status(401).json({ 
        error: 'Refresh token expirado',
        hint: 'Debes hacer login nuevamente'
      });
    } else {
      // Error genérico de verificación
      console.log('\u274c ERROR VERIFICANDO REFRESH TOKEN:', error);
      return res.status(403).json({ error: 'Refresh token inv\u00e1lido' });
    }
  }
});

// Logout (invalidar refresh token)
// Endpoint para cerrar sesión e invalidar el refresh token
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n\ud83d\udeaa LOGOUT REQUEST:');
  console.log('\ud83c\udf7b Refresh token para invalidar:', refreshToken ? 'Recibido' : 'No enviado');
  
  if (refreshToken) {
    // Si recibimos un refresh token, lo eliminamos de la lista válida
    const index = refreshTokens.indexOf(refreshToken);
    if (index > -1) {
      refreshTokens.splice(index, 1);
      console.log('\ud83d\uddd1\ufe0f Refresh token removido de la lista v\u00e1lida');
    }
  }
  
  console.log('\u2705 LOGOUT COMPLETADO');
  
  // Respondemos confirmando que se invalidó el refresh token
  res.json({
    success: true,
    message: 'Logout exitoso',
    note: '\ud83d\udca1 El access token seguir\u00e1 v\u00e1lido hasta que expire (15 min)'
  });
});

// Verificar token (\u00fatil para debugging)
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  
  console.log('\n\ud83d\udd0d VERIFICACI\u00d3N MANUAL DE TOKEN:');
  
  if (!token) {
    return res.status(400).json({ error: 'Token requerido' });
  }
  
  try {
    // Decodificar sin verificar (para ver contenido)
    const decoded = jwt.decode(token, { complete: true });
    console.log('\ud83d\udccb Token decodificado (sin verificar):', JSON.stringify(decoded, null, 2));
    
    // Verificar con secret
    const verified = jwt.verify(token, JWT_SECRET) as JwtPayload;
    console.log('\u2705 Token verificado exitosamente');
    
    res.json({
      valid: true,
      decoded: verified,
      header: decoded?.header,
      payload: decoded?.payload,
      isExpired: false,
      expiresAt: new Date(verified.exp! * 1000).toISOString()
    });
    
  } catch (error) {
    console.log('\u274c Token inv\u00e1lido:', error);
    
    // Intentar decodificar sin verificar para mostrar contenido
    try {
      const decoded = jwt.decode(token, { complete: true });
      res.status(401).json({
        valid: false,
        error: error instanceof Error ? error.message : 'Token inv\u00e1lido',
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
  console.log('\n\ud83d\udcca ESTADO DEL SERVIDOR:');
  console.log('\ud83d\udd04 Refresh tokens activos:', refreshTokens.length);
  
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
  console.log('\ud83d\ude80 JWT AUTH SERVER INICIADO');
  console.log(`\ud83d\udcf1 Puerto: ${PORT}`);
  console.log(`\ud83d\udd10 JWT Secret configurado: ${JWT_SECRET.substring(0, 20)}...`);
  console.log(`\ud83d\udd04 Refresh Secret configurado: ${JWT_REFRESH_SECRET.substring(0, 20)}...`);
  console.log('\ud83d\udca1 Endpoints disponibles en http://localhost:3000/api/');
});
