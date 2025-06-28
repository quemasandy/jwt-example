// Configuración de la API
const API_BASE = 'http://localhost:3000/api';

// Tipos TypeScript
interface User {
  id: string;
  username: string;
  role: string;
}

interface LoginResponse {
  success: boolean;
  message: string;
  user?: User;
  accessToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  note?: string;
}

interface TokenInfo {
  iat?: number;
  exp?: number;
  [key: string]: any;
}

// Clase para manejar tokens
class TokenManager {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  // Guardar tokens
  setTokens(accessToken: string, refreshToken: string) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    
    // Guardar en localStorage para persistencia
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    
    console.log('💾 Tokens guardados en memoria y localStorage');
  }

  // Obtener access token
  getAccessToken(): string | null {
    if (!this.accessToken) {
      this.accessToken = localStorage.getItem('accessToken');
    }
    return this.accessToken;
  }

  // Obtener refresh token
  getRefreshToken(): string | null {
    if (!this.refreshToken) {
      this.refreshToken = localStorage.getItem('refreshToken');
    }
    return this.refreshToken;
  }

  // Limpiar tokens
  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    
    console.log('🗑️ Tokens eliminados de memoria y localStorage');
  }

  // Verificar si hay tokens
  hasTokens(): boolean {
    return !!(this.getAccessToken() && this.getRefreshToken());
  }
}

// Instancia global del token manager
const tokenManager = new TokenManager();

// Elementos del DOM
const loginSection = document.getElementById('login-section')!;
const userSection = document.getElementById('user-section')!;
const loginForm = document.getElementById('login-form') as HTMLFormElement;
const usernameInput = document.getElementById('username') as HTMLInputElement;
const passwordInput = document.getElementById('password') as HTMLInputElement;
const authInfo = document.getElementById('auth-info')!;
const authStatus = document.getElementById('auth-status')!;
const userInfo = document.getElementById('user-info')!;
const responseArea = document.getElementById('response-area')!;
const tokenStorage = document.getElementById('token-storage')!;
const jwtInput = document.getElementById('jwt-input') as HTMLTextAreaElement;
const jwtOutput = document.getElementById('jwt-output')!;

// Botones
const getProfileBtn = document.getElementById('get-profile')!;
const getSecretBtn = document.getElementById('get-secret')!;
const refreshTokenBtn = document.getElementById('refresh-token')!;
const logoutBtn = document.getElementById('logout')!;
const refreshStorageBtn = document.getElementById('refresh-storage')!;
const decodeJwtBtn = document.getElementById('decode-jwt')!;

// 🔐 Función para realizar peticiones con JWT
async function fetchWithJWT(url: string, options: RequestInit = {}) {
  const accessToken = tokenManager.getAccessToken();
  
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
    console.log('🎫 Enviando request con Authorization header');
  }
  
  return fetch(url, {
    ...options,
    headers,
  });
}

// 🔄 Función para renovar access token
async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = tokenManager.getRefreshToken();
  
  if (!refreshToken) {
    console.log('❌ No hay refresh token disponible');
    return false;
  }
  
  try {
    console.log('🔄 Intentando renovar access token...');
    
    const response = await fetch(`${API_BASE}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    
    const data = await response.json();
    
    if (response.ok && data.accessToken) {
      console.log('✅ Access token renovado exitosamente');
      tokenManager.setTokens(data.accessToken, refreshToken);
      updateTokenDisplay();
      return true;
    } else {
      console.log('❌ Error renovando token:', data.error);
      return false;
    }
  } catch (error) {
    console.error('❌ Error en refresh:', error);
    return false;
  }
}

// 🔓 Función para decodificar JWT (sin verificar)
function decodeJWT(token: string): any {
  try {
    // JWT tiene 3 partes separadas por puntos: header.payload.signature
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('JWT malformado - debe tener 3 partes');
    }
    
    // Decodificar header y payload (están en base64url)
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    
    return { header, payload, signature: parts[2] };
  } catch (error) {
    throw new Error('Error decodificando JWT: ' + error);
  }
}

// 🎯 Mostrar información de tokens
function updateTokenDisplay() {
  const accessToken = tokenManager.getAccessToken();
  const refreshToken = tokenManager.getRefreshToken();
  
  if (accessToken) {
    try {
      const decoded = decodeJWT(accessToken);
      const now = Math.floor(Date.now() / 1000);
      const timeLeft = decoded.payload.exp - now;
      
      tokenStorage.innerHTML = `
<strong>🎫 ACCESS TOKEN:</strong>
Usuario: ${decoded.payload.username}
Rol: ${decoded.payload.role}
Expira: ${new Date(decoded.payload.exp * 1000).toLocaleString()}
Tiempo restante: ${timeLeft > 0 ? timeLeft + ' segundos' : 'EXPIRADO'}

<strong>🔄 REFRESH TOKEN:</strong>
${refreshToken ? 'Presente ✅' : 'No disponible ❌'}

<strong>📱 ALMACENAMIENTO:</strong>
localStorage: ${localStorage.getItem('accessToken') ? 'Sí' : 'No'}
Memoria: ${tokenManager.getAccessToken() ? 'Sí' : 'No'}
      `;
      tokenStorage.className = 'info-box success';
    } catch (error) {
      tokenStorage.innerHTML = 'Error decodificando token: ' + error;
      tokenStorage.className = 'info-box error';
    }
  } else {
    tokenStorage.innerHTML = 'No hay tokens almacenados';
    tokenStorage.className = 'info-box';
  }
}

// 📊 Verificar estado de autenticación
async function checkAuthStatus() {
  if (!tokenManager.hasTokens()) {
    showLoginSection();
    authInfo.innerHTML = '❌ No hay tokens almacenados';
    authStatus.className = 'status-box';
    return;
  }
  
  try {
    const response = await fetchWithJWT(`${API_BASE}/profile`);
    
    if (response.ok) {
      const data = await response.json();
      showUserSection(data.user);
      authInfo.innerHTML = `
        ✅ <strong>Autenticado con JWT</strong><br>
        👤 Usuario: ${data.user.username}<br>
        🎭 Rol: ${data.user.role}<br>
        ⏰ Token expira: ${data.tokenInfo.expiresAt}
      `;
      authStatus.className = 'status-box authenticated';
    } else if (response.status === 401) {
      // Token expirado, intentar renovar
      console.log('🔄 Access token expirado, intentando renovar...');
      const renewed = await refreshAccessToken();
      
      if (renewed) {
        // Reintentar verificación
        await checkAuthStatus();
      } else {
        showLoginSection();
        authInfo.innerHTML = '⏰ Tokens expirados - Necesitas hacer login';
        authStatus.className = 'status-box';
        tokenManager.clearTokens();
      }
    } else {
      throw new Error('Error verificando autenticación');
    }
  } catch (error) {
    console.error('❌ Error verificando estado:', error);
    showLoginSection();
    authInfo.innerHTML = '❌ Error verificando autenticación';
    authStatus.className = 'status-box error';
  }
  
  updateTokenDisplay();
}

// 🚪 Mostrar sección de login
function showLoginSection() {
  loginSection.style.display = 'block';
  userSection.style.display = 'none';
  responseArea.innerHTML = '';
}

// 👤 Mostrar sección de usuario
function showUserSection(user: User) {
  loginSection.style.display = 'none';
  userSection.style.display = 'block';
  userInfo.innerHTML = `
    <div class="success">
      👋 ¡Bienvenido, <strong>${user.username}</strong>!<br>
      🎭 Rol: <strong>${user.role}</strong><br>
      🔐 Autenticado con JWT - Sin estado en el servidor
    </div>
  `;
}

// 📝 Función para mostrar respuestas
function displayResponse(data: any, isError: boolean = false) {
  responseArea.innerHTML = JSON.stringify(data, null, 2);
  responseArea.className = `response-box ${isError ? 'error' : 'success'}`;
}

// EVENT LISTENERS

// 🔐 Login
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  
  if (!username || !password) {
    displayResponse({ error: 'Usuario y contraseña son requeridos' }, true);
    return;
  }
  
  try {
    console.log('🔐 Intentando login JWT...', { username });
    
    const response = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const data: LoginResponse = await response.json();
    
    if (data.success && data.accessToken && data.refreshToken) {
      console.log('✅ Login JWT exitoso!');
      
      // Guardar tokens
      tokenManager.setTokens(data.accessToken, data.refreshToken);
      
      // Limpiar formulario
      usernameInput.value = '';
      passwordInput.value = '';
      
      // Actualizar UI
      await checkAuthStatus();
      
      displayResponse({
        message: '✅ Login exitoso!',
        user: data.user,
        tokenInfo: {
          type: data.tokenType,
          expiresIn: data.expiresIn + ' segundos'
        },
        note: '🎫 JWT tokens guardados en localStorage'
      });
    } else {
      displayResponse(data, true);
    }
  } catch (error) {
    console.error('❌ Error en login:', error);
    displayResponse({ error: 'Error conectando con el servidor' }, true);
  }
});

// 👤 Obtener perfil
getProfileBtn.addEventListener('click', async () => {
  try {
    const response = await fetchWithJWT(`${API_BASE}/profile`);
    const data = await response.json();
    
    if (response.ok) {
      displayResponse({
        message: '✅ Perfil obtenido exitosamente',
        ...data,
        note: '🎫 Datos extraídos directamente del JWT payload'
      });
    } else {
      displayResponse(data, true);
      if (response.status === 401) {
        await checkAuthStatus();
      }
    }
  } catch (error) {
    console.error('❌ Error obteniendo perfil:', error);
    displayResponse({ error: 'Error conectando con el servidor' }, true);
  }
});

// 🔒 Obtener datos secretos
getSecretBtn.addEventListener('click', async () => {
  try {
    const response = await fetchWithJWT(`${API_BASE}/secret-data`);
    const data = await response.json();
    
    if (response.ok) {
      displayResponse({
        message: '🔒 Datos secretos obtenidos',
        ...data,
        note: '🎭 Contenido basado en el rol del JWT'
      });
    } else {
      displayResponse(data, true);
      if (response.status === 401) {
        await checkAuthStatus();
      }
    }
  } catch (error) {
    console.error('❌ Error obteniendo datos secretos:', error);
    displayResponse({ error: 'Error conectando con el servidor' }, true);
  }
});

// 🔄 Renovar token
refreshTokenBtn.addEventListener('click', async () => {
  const success = await refreshAccessToken();
  
  if (success) {
    displayResponse({
      message: '🔄 Access token renovado exitosamente',
      note: '🎫 Nuevo token guardado y listo para usar'
    });
    await checkAuthStatus();
  } else {
    displayResponse({
      error: '❌ No se pudo renovar el token',
      hint: 'Posiblemente el refresh token expiró'
    }, true);
    tokenManager.clearTokens();
    await checkAuthStatus();
  }
});

// 🚪 Logout
logoutBtn.addEventListener('click', async () => {
  const refreshToken = tokenManager.getRefreshToken();
  
  try {
    await fetch(`${API_BASE}/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    
    tokenManager.clearTokens();
    await checkAuthStatus();
    
    displayResponse({
      message: '🚪 Logout exitoso',
      note: '🗑️ Tokens eliminados del cliente y servidor'
    });
  } catch (error) {
    console.error('❌ Error en logout:', error);
    tokenManager.clearTokens();
    await checkAuthStatus();
  }
});

// 🔄 Actualizar storage
refreshStorageBtn.addEventListener('click', updateTokenDisplay);

// 🔍 Decodificar JWT
decodeJwtBtn.addEventListener('click', () => {
  const token = jwtInput.value.trim();
  
  if (!token) {
    jwtOutput.innerHTML = 'Por favor ingresa un JWT';
    jwtOutput.className = 'info-box error';
    return;
  }
  
  try {
    const decoded = decodeJWT(token);
    const now = Math.floor(Date.now() / 1000);
    
    jwtOutput.innerHTML = `
<strong>🔍 JWT DECODIFICADO:</strong>

<strong>📋 HEADER:</strong>
${JSON.stringify(decoded.header, null, 2)}

<strong>📦 PAYLOAD:</strong>
${JSON.stringify(decoded.payload, null, 2)}

<strong>🔐 SIGNATURE:</strong>
${decoded.signature}

<strong>⏰ INFORMACIÓN DE TIEMPO:</strong>
Emitido: ${decoded.payload.iat ? new Date(decoded.payload.iat * 1000).toLocaleString() : 'No especificado'}
Expira: ${decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toLocaleString() : 'No especificado'}
Estado: ${decoded.payload.exp && decoded.payload.exp < now ? '❌ EXPIRADO' : '✅ VÁLIDO'}
    `;
    jwtOutput.className = 'info-box success';
  } catch (error) {
    jwtOutput.innerHTML = 'Error: ' + error;
    jwtOutput.className = 'info-box error';
  }
});

// 🚀 Inicializar aplicación
console.log('🚀 Iniciando aplicación JWT...');
checkAuthStatus();
updateTokenDisplay();

// Auto-refresh del display cada 5 segundos
setInterval(updateTokenDisplay, 5000);
