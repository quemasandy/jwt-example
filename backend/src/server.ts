import express from 'express';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const app = express();
const PORT = 3000;

// \ud83d\udd11 Secretos JWT (en producci\u00f3n usar variables de entorno)
const JWT_SECRET = 'mi-super-secreto-jwt-para-firmar-tokens';
const JWT_REFRESH_SECRET = 'mi-secreto-para-refresh-tokens';

// Configuraci\u00f3n de middlewares
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));

app.use(express.json());

// \ud83d\udcca Usuarios simulados
const users = [
  { id: '1', username: 'juan', password: '123456', role: 'user' },
  { id: '2', username: 'maria', password: 'password', role: 'admin' },
  { id: '3', username: 'admin', password: 'admin123', role: 'superadmin' }
];

// \ud83d\udc84 Storage simple para refresh tokens (en producci\u00f3n usar Redis/DB)
const refreshTokens: string[] = [];

// \ud83c\udff7\ufe0f Tipos TypeScript para JWT
interface JwtPayload {
  userId: string;
  username: string;
  role: string;
  iat?: number;
  exp?: number;
}

interface RefreshTokenPayload {
  userId: string;
  tokenVersion: number;
  iat?: number;
  exp?: number;
}

// \ud83d\udd10 Funci\u00f3n para crear Access Token
function createAccessToken(user: typeof users[0]): string {
  const payload: JwtPayload = {
    userId: user.id,
    username: user.username,
    role: user.role
  };

  console.log('\ud83c\udf7b CREANDO ACCESS TOKEN:');
  console.log('\ud83d\udccb Payload:', JSON.stringify(payload, null, 2));
  
  const token = jwt.sign(payload, JWT_SECRET, { 
    expiresIn: '15m' // Token de acceso corto
  });
  
  console.log('\ud83d\udd10 Token firmado (primeros 50 chars):', token.substring(0, 50) + '...');
  console.log('\u23f0 Expira en: 15 minutos');
  
  return token;
}

// \ud83d\udd04 Funci\u00f3n para crear Refresh Token
function createRefreshToken(userId: string): string {
  const payload: RefreshTokenPayload = {
    userId,
    tokenVersion: 1 // Versi\u00f3n para invalidar tokens
  };

  console.log('\ud83d\udd04 CREANDO REFRESH TOKEN:');
  console.log('\ud83d\udccb Payload:', JSON.stringify(payload, null, 2));
  
  const token = jwt.sign(payload, JWT_REFRESH_SECRET, { 
    expiresIn: '7d' // Refresh token largo
  });
  
  console.log('\ud83d\udd10 Refresh token creado');
  console.log('\u23f0 Expira en: 7 d\u00edas');
  
  // Guardar en nuestra "base de datos" de refresh tokens
  refreshTokens.push(token);
  
  return token;
}

// \ud83d\udd12 Middleware para verificar Access Token
const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.log('\n\ud83d\udd0d VERIFICANDO ACCESS TOKEN...');
  
  // Obtener token del header Authorization
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
    (req as any).user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      console.log('\u23f0 TOKEN EXPIRADO');
      console.log('\ud83d\udcc5 Expir\u00f3 en:', error.expiredAt);
      return res.status(401).json({ 
        error: 'Token expirado',
        expiredAt: error.expiredAt,
        hint: 'Usa el refresh token para obtener uno nuevo'
      });
    } else if (error instanceof jwt.JsonWebTokenError) {
      console.log('\u274c TOKEN INV\u00c1LIDO:', error.message);
      return res.status(403).json({ 
        error: 'Token inv\u00e1lido',
        details: error.message 
      });
    } else {
      console.log('\ud83d\udca5 ERROR INESPERADO:', error);
      return res.status(500).json({ error: 'Error verificando token' });
    }
  }
};

// \ud83d\udeaa RUTAS

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('\n\ud83d\udd10 INTENTO DE LOGIN JWT:');
  console.log('\ud83d\udc64 Usuario:', username);
  console.log('\ud83d\uddd1 Password:', password ? '***' : 'No enviado');
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    console.log('\u2705 CREDENCIALES V\u00c1LIDAS');
    console.log('\ud83d\udc64 Usuario encontrado:', { id: user.id, username: user.username, role: user.role });
    
    // Crear tokens
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user.id);
    
    console.log('\n\ud83d\udce4 ENVIANDO RESPUESTA CON TOKENS...');
    
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
    console.log('\u274c CREDENCIALES INV\u00c1LIDAS');
    res.status(401).json({ 
      success: false, 
      message: 'Usuario o contrase\u00f1a incorrectos' 
    });
  }
});

// Obtener perfil (requiere autenticaci\u00f3n)
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  console.log('\n\ud83d\udc64 ACCESO A PERFIL:');
  console.log('\u2705 Usuario autenticado:', user.username);
  console.log('\ud83c\udf9d\ufe0f Rol:', user.role);
  
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
app.get('/api/secret-data', authenticateToken, (req, res) => {
  const user = (req as any).user as JwtPayload;
  
  console.log('\n\ud83d\udd12 ACCESO A DATOS SECRETOS:');
  console.log('\ud83d\udc64 Usuario:', user.username);
  console.log('\ud83c\udf9d\ufe0f Rol:', user.role);
  
  // Datos diferentes seg\u00fan el rol
  let secretData;
  switch (user.role) {
    case 'superadmin':
      secretData = '\ud83d\udc51 Datos ultra secretos del super admin';
      break;
    case 'admin':
      secretData = '\ud83d\udd10 Datos secretos del admin';
      break;
    default:
      secretData = '\ud83d\udcca Datos b\u00e1sicos del usuario';
  }
  
  res.json({
    success: true,
    secretData,
    userRole: user.role,
    message: `\u00a1Hola ${user.username}! Estos son tus datos seg\u00fan tu rol.`,
    timestamp: new Date().toISOString()
  });
});

// Refresh Token (obtener nuevo access token)
app.post('/api/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n\ud83d\udd04 REFRESH TOKEN REQUEST:');
  console.log('\ud83c\udf7b Refresh token recibido:', refreshToken ? '\u00a1S\u00ed!' : 'No');
  
  if (!refreshToken) {
    console.log('\u274c No se envi\u00f3 refresh token');
    return res.status(401).json({ 
      error: 'Refresh token requerido',
      hint: 'Env\u00eda { "refreshToken": "tu-refresh-token" }'
    });
  }
  
  // Verificar que el refresh token est\u00e9 en nuestra lista
  if (!refreshTokens.includes(refreshToken)) {
    console.log('\u274c Refresh token no encontrado en la lista v\u00e1lida');
    return res.status(403).json({ 
      error: 'Refresh token inv\u00e1lido o revocado' 
    });
  }
  
  try {
    console.log('\ud83d\udd13 Verificando refresh token...');
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as RefreshTokenPayload;
    
    console.log('\u2705 REFRESH TOKEN V\u00c1LIDO:');
    console.log('\ud83d\udc64 User ID:', decoded.userId);
    console.log('\ud83d\udfe2 Token version:', decoded.tokenVersion);
    
    // Buscar usuario
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      console.log('\u274c Usuario no encontrado');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Crear nuevo access token
    const newAccessToken = createAccessToken(user);
    
    console.log('\ud83c\udf7b NUEVO ACCESS TOKEN GENERADO');
    
    res.json({
      success: true,
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      expiresIn: 900, // 15 minutos
      message: 'Access token renovado exitosamente'
    });
    
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      console.log('\u23f0 REFRESH TOKEN EXPIRADO');
      // Remover de la lista de tokens v\u00e1lidos
      const index = refreshTokens.indexOf(refreshToken);
      if (index > -1) refreshTokens.splice(index, 1);
      
      return res.status(401).json({ 
        error: 'Refresh token expirado',
        hint: 'Debes hacer login nuevamente'
      });
    } else {
      console.log('\u274c ERROR VERIFICANDO REFRESH TOKEN:', error);
      return res.status(403).json({ error: 'Refresh token inv\u00e1lido' });
    }
  }
});

// Logout (invalidar refresh token)
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  
  console.log('\n\ud83d\udeaa LOGOUT REQUEST:');
  console.log('\ud83c\udf7b Refresh token para invalidar:', refreshToken ? 'Recibido' : 'No enviado');
  
  if (refreshToken) {
    // Remover refresh token de la lista v\u00e1lida
    const index = refreshTokens.indexOf(refreshToken);
    if (index > -1) {
      refreshTokens.splice(index, 1);
      console.log('\ud83d\uddd1\ufe0f Refresh token removido de la lista v\u00e1lida');
    }
  }
  
  console.log('\u2705 LOGOUT COMPLETADO');
  
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
