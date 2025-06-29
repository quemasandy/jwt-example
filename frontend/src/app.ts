// ===================================================================================================
// 🌐 CONFIGURACIÓN DE LA API Y CONSTANTES GLOBALES
// ===================================================================================================

// URL base del servidor backend que implementa la autenticación JWT
// En producción, esta URL debería configurarse através de variables de entorno
// para permitir diferentes endpoints según el ambiente (desarrollo, staging, producción)
// Vite expone variables de entorno que empiecen con VITE_ al frontend
const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3000/api';

// ===================================================================================================
// 🏷️ DEFINICIONES DE TIPOS TYPESCRIPT PARA JWT Y AUTENTICACIÓN
// ===================================================================================================

// Interfaz que define la estructura de un usuario en el sistema
// Esta interfaz representa los datos del usuario que se almacenan en el payload del JWT
// y que se utilizan a lo largo de la aplicación para mostrar información del usuario autenticado
interface User {
  id: string;       // Identificador único del usuario en la base de datos
  username: string; // Nombre de usuario único utilizado para el login
  role: string;     // Rol del usuario (user, admin, superadmin) que determina permisos
}

// Interfaz que define la estructura completa de la respuesta del endpoint de login
// Esta respuesta contiene tanto los tokens JWT como información adicional del usuario
// El servidor devuelve esta estructura cuando las credenciales son válidas
interface LoginResponse {
  success: boolean;        // Indica si el login fue exitoso
  message: string;         // Mensaje descriptivo del resultado del login
  user?: User;            // Información del usuario (solo presente si success=true)
  accessToken?: string;    // Token JWT de acceso con tiempo de vida corto (15 min)
  refreshToken?: string;   // Token JWT de refresco con tiempo de vida largo (7 días)
  tokenType?: string;      // Tipo de token, típicamente "Bearer" para JWT
  expiresIn?: number;      // Tiempo de expiración del access token en segundos
  note?: string;           // Nota adicional con información sobre el uso de tokens
}

// Interfaz para la información temporal contenida en los tokens JWT
// Los tokens JWT incluyen timestamps estándar (iat, exp) que permiten validar
// cuándo fue emitido el token y cuándo expira
interface TokenInfo {
  iat?: number;           // "Issued At" - timestamp de cuando se emitió el token
  exp?: number;           // "Expires" - timestamp de cuando expira el token
  [key: string]: any;     // Permite otras propiedades adicionales en el token
}

// ===================================================================================================
// 💾 CLASE TOKENMANGER - GESTIÓN CENTRAL DE TOKENS JWT
// ===================================================================================================

// Clase responsable de la gestión completa del ciclo de vida de los tokens JWT
// Implementa una estrategia de almacenamiento dual: memoria + localStorage
// Esta clase centraliza todas las operaciones relacionadas con tokens para mantener
// consistencia y facilitar el mantenimiento del código
class TokenManager {
  // Almacenamiento en memoria para acceso rápido durante la sesión activa
  // Los tokens en memoria se pierden al recargar la página, pero son más seguros
  // contra ataques XSS ya que no están accesibles através del objeto window
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  // ===============================================================================================
  // 💾 MÉTODO PARA GUARDAR TOKENS EN MEMORIA Y LOCALSTORAGE
  // ===============================================================================================
  
  // Almacena los tokens tanto en memoria como en localStorage para persistencia
  // Estrategia dual permite: velocidad (memoria) + persistencia (localStorage)
  // CONSIDERACIONES DE SEGURIDAD:
  // - localStorage es vulnerable a XSS pero persiste entre sesiones
  // - Memoria es más segura pero se pierde al recargar
  // - En producción considerar usar cookies HttpOnly para mayor seguridad
  setTokens(accessToken: string, refreshToken: string) {
    // Almacenar en memoria para acceso inmediato y eficiente
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    
    // Persistir en localStorage para mantener sesión através recargas de página
    // Esto permite que el usuario permanezca logueado al cerrar/abrir la pestaña
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    
    // Log informativo para debugging y seguimiento del flujo de autenticación
    console.log('💾 Tokens guardados en memoria y localStorage');
    console.log('🔐 Access token length:', accessToken.length);
    console.log('🔄 Refresh token length:', refreshToken.length);
  }

  // ===============================================================================================
  // 🎫 MÉTODO PARA OBTENER EL ACCESS TOKEN
  // ===============================================================================================
  
  // Obtiene el access token con estrategia de fallback: memoria → localStorage
  // Primero intenta obtener de memoria (más rápido), si no está disponible
  // lo recupera de localStorage (persistencia através recargas)
  getAccessToken(): string | null {
    // Si no está en memoria, intentar recuperar de localStorage
    // Esto ocurre típicamente después de recargar la página
    if (!this.accessToken) {
      this.accessToken = localStorage.getItem('accessToken');
      if (this.accessToken) {
        console.log('🔄 Access token recuperado de localStorage');
      }
    }
    return this.accessToken;
  }

  // ===============================================================================================
  // 🔄 MÉTODO PARA OBTENER EL REFRESH TOKEN
  // ===============================================================================================
  
  // Similar al access token, pero para el refresh token de larga duración
  // El refresh token se usa para obtener nuevos access tokens sin requerir login
  getRefreshToken(): string | null {
    // Aplicar la misma estrategia de fallback: memoria → localStorage
    if (!this.refreshToken) {
      this.refreshToken = localStorage.getItem('refreshToken');
      if (this.refreshToken) {
        console.log('🔄 Refresh token recuperado de localStorage');
      }
    }
    return this.refreshToken;
  }

  // ===============================================================================================
  // 🗑️ MÉTODO PARA LIMPIAR TOKENS (LOGOUT)
  // ===============================================================================================
  
  // Limpia completamente todos los tokens del cliente
  // Esto efectivamente "desloguea" al usuario localmente
  // IMPORTANTE: También se debe notificar al servidor para invalidar el refresh token
  clearTokens() {
    // Limpiar memoria
    this.accessToken = null;
    this.refreshToken = null;
    
    // Limpiar localStorage para eliminar persistencia
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    
    // Log para confirmar limpieza exitosa
    console.log('🗑️ Tokens eliminados de memoria y localStorage');
    console.log('🔓 Usuario deslogueado localmente');
  }

  // ===============================================================================================
  // ✅ MÉTODO PARA VERIFICAR PRESENCIA DE TOKENS
  // ===============================================================================================
  
  // Verifica si el usuario tiene ambos tokens necesarios para la autenticación
  // Retorna true solo si tanto access como refresh token están disponibles
  // Esto no valida que los tokens sean válidos, solo que existen
  hasTokens(): boolean {
    const hasAccess = !!this.getAccessToken();
    const hasRefresh = !!this.getRefreshToken();
    
    console.log('🔍 Verificación de tokens:', { 
      hasAccess, 
      hasRefresh, 
      bothPresent: hasAccess && hasRefresh 
    });
    
    return hasAccess && hasRefresh;
  }
}

// ===================================================================================================
// 🌍 INSTANCIA GLOBAL DEL GESTOR DE TOKENS
// ===================================================================================================

// Crear una instancia global única (singleton pattern) del TokenManager
// Esto asegura que toda la aplicación use la misma instancia para gestionar tokens
// evitando inconsistencias y problemas de sincronización
const tokenManager = new TokenManager();

// ===================================================================================================
// 🎨 REFERENCIAS A ELEMENTOS DEL DOM
// ===================================================================================================

// Obtener referencias a todos los elementos del DOM que la aplicación necesita manipular
// Usar el operador ! (non-null assertion) porque sabemos que estos elementos existen en el HTML
// En una aplicación real, sería recomendable agregar verificaciones de existencia

// Secciones principales de la interfaz
const loginSection = document.getElementById('login-section')!;  // Formulario de login
const userSection = document.getElementById('user-section')!;    // Panel de usuario autenticado

// Elementos del formulario de login
const loginForm = document.getElementById('login-form') as HTMLFormElement;
const usernameInput = document.getElementById('username') as HTMLInputElement;
const passwordInput = document.getElementById('password') as HTMLInputElement;

// Elementos de información y estado
const authInfo = document.getElementById('auth-info')!;           // Información de autenticación
const authStatus = document.getElementById('auth-status')!;       // Estado visual de auth
const userInfo = document.getElementById('user-info')!;          // Información del usuario
const responseArea = document.getElementById('response-area')!;   // Área de respuestas API
const tokenStorage = document.getElementById('token-storage')!;   // Información de tokens

// Elementos para herramientas JWT
const jwtInput = document.getElementById('jwt-input') as HTMLTextAreaElement;  // Input para JWT
const jwtOutput = document.getElementById('jwt-output')!;                      // Output decodificado

// Botones de acción
const getProfileBtn = document.getElementById('get-profile')!;      // Obtener perfil de usuario
const getSecretBtn = document.getElementById('get-secret')!;        // Obtener datos secretos
const refreshTokenBtn = document.getElementById('refresh-token')!;  // Renovar access token
const logoutBtn = document.getElementById('logout')!;              // Cerrar sesión
const refreshStorageBtn = document.getElementById('refresh-storage')!; // Actualizar vista storage
const decodeJwtBtn = document.getElementById('decode-jwt')!;        // Decodificar JWT manual

// ===================================================================================================
// 🔐 FUNCIÓN PARA REALIZAR PETICIONES HTTP CON AUTENTICACIÓN JWT
// ===================================================================================================

// Función wrapper que automatiza la inclusión del token JWT en las peticiones HTTP
// Esta función extiende fetch() para agregar automáticamente el header Authorization
// Esto centraliza la lógica de autenticación y evita repetir código en cada petición
async function fetchWithJWT(url: string, options: RequestInit = {}) {
  console.log('🌐 Iniciando petición autenticada a:', url);
  
  // Obtener el access token actual del TokenManager
  const accessToken = tokenManager.getAccessToken();
  
  // Crear headers y asegurar que Content-Type esté configurado
  // Headers se gestionan através de la clase Headers para mayor compatibilidad
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  
  // Si tenemos un access token, agregarlo al header Authorization
  // El formato Bearer es el estándar para tokens JWT en HTTP
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
    console.log('🎫 Enviando request con Authorization header');
    console.log('🔍 Token preview:', accessToken.substring(0, 20) + '...');
  } else {
    console.log('⚠️ No hay access token disponible - petición sin autenticación');
  }
  
  // Realizar la petición HTTP con los headers modificados
  // Spread operator (...) preserva todas las opciones originales
  return fetch(url, {
    ...options,
    headers,
  });
}

// ===================================================================================================
// 🔄 FUNCIÓN PARA RENOVAR EL ACCESS TOKEN USANDO EL REFRESH TOKEN
// ===================================================================================================

// Implementa el flujo de renovación automática de tokens JWT
// Cuando un access token expira, esta función intenta obtener uno nuevo
// usando el refresh token de larga duración, evitando que el usuario deba hacer login
async function refreshAccessToken(): Promise<boolean> {
  console.log('🔄 Iniciando proceso de renovación de access token...');
  
  // Obtener el refresh token del almacenamiento
  const refreshToken = tokenManager.getRefreshToken();
  
  // Verificar que tenemos un refresh token disponible
  if (!refreshToken) {
    console.log('❌ No hay refresh token disponible para renovación');
    console.log('🔐 El usuario deberá hacer login nuevamente');
    return false;
  }
  
  try {
    console.log('📤 Enviando refresh token al servidor...');
    
    // Realizar petición al endpoint de refresh
    // NOTA: Esta petición NO usa fetchWithJWT porque no necesita access token
    const response = await fetch(`${API_BASE}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    
    // Parsear la respuesta del servidor
    const data = await response.json();
    console.log('📥 Respuesta del servidor de refresh:', data);
    
    // Verificar si la renovación fue exitosa
    if (response.ok && data.accessToken) {
      console.log('✅ Access token renovado exitosamente');
      console.log('⏰ Nuevo token válido por 15 minutos');
      
      // Guardar el nuevo access token (mantener el mismo refresh token)
      tokenManager.setTokens(data.accessToken, refreshToken);
      
      // Actualizar la interfaz para reflejar el nuevo estado
      updateTokenDisplay();
      return true;
    } else {
      // Renovación falló - probablemente refresh token expirado o inválido
      console.log('❌ Error renovando token:', data.error);
      console.log('🔐 Refresh token posiblemente expirado o revocado');
      return false;
    }
  } catch (error) {
    // Error de red o del servidor
    console.error('❌ Error de comunicación en refresh:', error);
    return false;
  }
}

// ===================================================================================================
// 🔓 FUNCIÓN PARA DECODIFICAR TOKENS JWT (SIN VERIFICACIÓN DE FIRMA)
// ===================================================================================================

// Decodifica un token JWT para inspeccionar su contenido
// IMPORTANTE: Esta función NO verifica la firma del token, solo decodifica el contenido
// La verificación de firma debe realizarse en el servidor por seguridad
function decodeJWT(token: string): any {
  console.log('🔍 Iniciando decodificación de JWT...');
  
  try {
    // Un JWT válido siempre tiene exactamente 3 partes separadas por puntos
    // Formato: header.payload.signature
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('JWT malformado - debe tener exactamente 3 partes (header.payload.signature)');
    }
    
    console.log('📋 JWT tiene estructura válida (3 partes)');
    
    // Decodificar header y payload que están codificados en base64url
    // base64url es similar a base64 pero usa - en lugar de + y _ en lugar de /
    // y no incluye padding (=) al final
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    
    console.log('✅ JWT decodificado exitosamente');
    console.log('🏷️ Header:', header);
    console.log('📦 Payload:', payload);
    
    // Retornar las tres partes del JWT
    return { 
      header,      // Información sobre el algoritmo y tipo de token
      payload,     // Datos del usuario y metadatos del token
      signature: parts[2]  // Firma digital (no decodificable sin la clave)
    };
  } catch (error) {
    console.error('❌ Error decodificando JWT:', error);
    throw new Error('Error decodificando JWT: ' + error);
  }
}

// ===================================================================================================
// 🎯 FUNCIÓN PARA ACTUALIZAR LA VISUALIZACIÓN DE TOKENS EN LA INTERFAZ
// ===================================================================================================

// Actualiza la sección de información de tokens en tiempo real
// Muestra detalles del access token, estado del refresh token y información de almacenamiento
function updateTokenDisplay() {
  console.log('🔄 Actualizando visualización de tokens...');
  
  const accessToken = tokenManager.getAccessToken();
  const refreshToken = tokenManager.getRefreshToken();
  
  // Solo mostrar información si tenemos un access token
  if (accessToken) {
    try {
      // Decodificar el access token para mostrar su contenido
      const decoded = decodeJWT(accessToken);
      
      // Calcular tiempo restante hasta expiración
      const now = Math.floor(Date.now() / 1000);  // Timestamp actual en segundos
      const timeLeft = decoded.payload.exp - now;  // Segundos hasta expiración
      
      // Generar HTML informativo con todos los detalles relevantes
      tokenStorage.innerHTML = `
<strong>🎫 ACCESS TOKEN:</strong>
Usuario: ${decoded.payload.username}
Rol: ${decoded.payload.role}
Emitido: ${new Date(decoded.payload.iat * 1000).toLocaleString()}
Expira: ${new Date(decoded.payload.exp * 1000).toLocaleString()}
Tiempo restante: ${timeLeft > 0 ? timeLeft + ' segundos' : '⚠️ EXPIRADO'}

<strong>🔄 REFRESH TOKEN:</strong>
Estado: ${refreshToken ? '✅ Presente y disponible' : '❌ No disponible'}
${refreshToken ? 'Válido por: 7 días desde login' : 'Requiere nuevo login'}

<strong>📱 ALMACENAMIENTO:</strong>
localStorage: ${localStorage.getItem('accessToken') ? '✅ Persistido' : '❌ No encontrado'}
Memoria: ${tokenManager.getAccessToken() ? '✅ En memoria' : '❌ No disponible'}
Sincronización: ${localStorage.getItem('accessToken') === tokenManager.getAccessToken() ? '✅ Sincronizado' : '⚠️ Desincronizado'}
      `;
      
      // Aplicar estilo visual para tokens válidos
      tokenStorage.className = 'info-box success';
      
      console.log('✅ Display de tokens actualizado exitosamente');
    } catch (error) {
      // Error decodificando token - probablemente corrupto
      console.error('❌ Error decodificando token para display:', error);
      tokenStorage.innerHTML = 'Error decodificando token: ' + error;
      tokenStorage.className = 'info-box error';
    }
  } else {
    // No hay tokens disponibles
    console.log('📭 No hay tokens para mostrar');
    tokenStorage.innerHTML = `
<strong>📭 NO HAY TOKENS ALMACENADOS</strong>

Para acceder a recursos protegidos:
1. Inicia sesión con tus credenciales
2. Los tokens se guardarán automáticamente
3. El access token se renovará automáticamente

<strong>🔐 ESTADO ACTUAL:</strong>
- Sin autenticación activa
- Acceso limitado a recursos públicos únicamente
    `;
    tokenStorage.className = 'info-box';
  }
}

// ===================================================================================================
// 📊 FUNCIÓN PARA VERIFICAR EL ESTADO DE AUTENTICACIÓN ACTUAL
// ===================================================================================================

// Verifica si el usuario está autenticado y actualiza la interfaz accordingly
// Esta función coordina toda la lógica de estado de autenticación de la aplicación
async function checkAuthStatus() {
  console.log('🔍 Verificando estado de autenticación...');
  
  // Primer check: ¿tenemos tokens almacenados?
  if (!tokenManager.hasTokens()) {
    console.log('❌ No hay tokens - mostrando pantalla de login');
    showLoginSection();
    authInfo.innerHTML = '❌ No hay tokens almacenados - Inicia sesión para continuar';
    authStatus.className = 'status-box';
    return;
  }
  
  console.log('🎫 Tokens encontrados - verificando validez con servidor...');
  
  try {
    // Intentar acceder a un endpoint protegido para validar el token
    // Usamos /profile porque requiere autenticación pero no permisos especiales
    const response = await fetchWithJWT(`${API_BASE}/profile`);
    
    if (response.ok) {
      // Token válido - usuario autenticado exitosamente
      const data = await response.json();
      console.log('✅ Usuario autenticado correctamente:', data.user);
      
      // Mostrar interfaz de usuario autenticado
      showUserSection(data.user);
      
      // Mostrar información detallada de autenticación
      authInfo.innerHTML = `
        ✅ <strong>Autenticado con JWT</strong><br>
        👤 Usuario: ${data.user.username}<br>
        🎭 Rol: ${data.user.role}<br>
        ⏰ Token expira: ${data.tokenInfo.expiresAt}<br>
        🔄 Renovación: Automática antes de expirar
      `;
      authStatus.className = 'status-box authenticated';
      
    } else if (response.status === 401) {
      // Token expirado - intentar renovación automática
      console.log('⏰ Access token expirado - iniciando renovación automática...');
      const renewed = await refreshAccessToken();
      
      if (renewed) {
        console.log('🔄 Token renovado - reintentando verificación...');
        // Recursivamente verificar estado con el nuevo token
        await checkAuthStatus();
      } else {
        console.log('❌ No se pudo renovar token - requiere login manual');
        // Renovación falló - limpiar tokens y mostrar login
        showLoginSection();
        authInfo.innerHTML = '⏰ Tokens expirados - Es necesario iniciar sesión nuevamente';
        authStatus.className = 'status-box';
        tokenManager.clearTokens();
      }
    } else {
      // Otro tipo de error del servidor
      throw new Error(`Error del servidor: ${response.status} ${response.statusText}`);
    }
  } catch (error) {
    // Error de red o servidor no disponible
    console.error('❌ Error verificando estado de autenticación:', error);
    showLoginSection();
    authInfo.innerHTML = '❌ Error de comunicación con el servidor - Verifica conexión';
    authStatus.className = 'status-box error';
  }
  
  // Actualizar display de tokens independientemente del resultado
  updateTokenDisplay();
}

// ===================================================================================================
// 🚪 FUNCIÓN PARA MOSTRAR LA SECCIÓN DE LOGIN
// ===================================================================================================

// Configura la interfaz para mostrar el formulario de login
// Oculta las secciones de usuario autenticado y limpia información previa
function showLoginSection() {
  console.log('🚪 Mostrando sección de login');
  
  // Mostrar formulario de login y ocultar panel de usuario
  loginSection.style.display = 'block';
  userSection.style.display = 'none';
  
  // Limpiar área de respuestas previas
  responseArea.innerHTML = '';
  
  console.log('📋 Formulario de login listo para credenciales');
}

// ===================================================================================================
// 👤 FUNCIÓN PARA MOSTRAR LA SECCIÓN DE USUARIO AUTENTICADO
// ===================================================================================================

// Configura la interfaz para un usuario autenticado exitosamente
// Muestra información del usuario y oculta el formulario de login
function showUserSection(user: User) {
  console.log('👤 Mostrando sección de usuario autenticado:', user.username);
  
  // Ocultar login y mostrar panel de usuario
  loginSection.style.display = 'none';
  userSection.style.display = 'block';
  
  // Mostrar información personalizada del usuario
  userInfo.innerHTML = `
    <div class="success">
      👋 ¡Bienvenido, <strong>${user.username}</strong>!<br>
      🎭 Rol: <strong>${user.role}</strong><br>
      🔐 Autenticado con JWT - Sin estado en el servidor<br>
      🛡️ Acceso seguro a recursos protegidos habilitado
    </div>
  `;
  
  console.log('✅ Panel de usuario configurado exitosamente');
}

// ===================================================================================================
// 📝 FUNCIÓN PARA MOSTRAR RESPUESTAS DE LA API EN LA INTERFAZ
// ===================================================================================================

// Función utilitaria para mostrar respuestas de la API de manera consistente
// Formatea y estiliza las respuestas para mejor legibilidad
function displayResponse(data: any, isError: boolean = false) {
  console.log('📝 Mostrando respuesta en interfaz:', { isError, dataType: typeof data });
  
  // Formatear JSON con indentación para mejor legibilidad
  responseArea.innerHTML = JSON.stringify(data, null, 2);
  
  // Aplicar estilos según tipo de respuesta (éxito o error)
  responseArea.className = `response-box ${isError ? 'error' : 'success'}`;
  
  console.log('✅ Respuesta mostrada en interfaz');
}

// ===================================================================================================
// 🎮 EVENT LISTENERS - MANEJO DE INTERACCIONES DEL USUARIO
// ===================================================================================================

// ===================================================================================================
// 🔐 EVENT LISTENER: FORMULARIO DE LOGIN
// ===================================================================================================

// Maneja el proceso completo de autenticación cuando el usuario envía el formulario
loginForm.addEventListener('submit', async (e) => {
  // Prevenir envío tradicional del formulario (evitar recarga de página)
  e.preventDefault();
  
  console.log('🔐 Procesando intento de login...');
  
  // Obtener y limpiar datos del formulario
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  
  // Validación básica en el frontend
  if (!username || !password) {
    console.log('❌ Validación falló: campos requeridos vacíos');
    displayResponse({ 
      error: 'Usuario y contraseña son requeridos',
      hint: 'Por favor completa ambos campos antes de continuar'
    }, true);
    return;
  }
  
  console.log('📤 Enviando credenciales al servidor...', { username });
  
  try {
    // Realizar petición de login al servidor
    // NOTA: La contraseña se envía en texto plano porque este es un demo
    // En producción usar HTTPS obligatorio y considerar técnicas adicionales
    const response = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    // Parsear respuesta del servidor
    const data: LoginResponse = await response.json();
    console.log('📥 Respuesta de login recibida:', { success: data.success });
    
    // Verificar si el login fue exitoso
    if (data.success && data.accessToken && data.refreshToken) {
      console.log('✅ Login JWT exitoso - tokens recibidos');
      
      // Almacenar tokens JWT para futuras peticiones
      tokenManager.setTokens(data.accessToken, data.refreshToken);
      
      // Limpiar formulario por seguridad y UX
      usernameInput.value = '';
      passwordInput.value = '';
      
      // Actualizar interfaz al estado autenticado
      await checkAuthStatus();
      
      // Mostrar confirmación exitosa al usuario
      displayResponse({
        message: '✅ Login exitoso - Acceso autorizado',
        user: data.user,
        tokenInfo: {
          type: data.tokenType,
          expiresIn: data.expiresIn + ' segundos',
          autoRefresh: 'Activado'
        },
        note: '🎫 JWT tokens almacenados y configurados automáticamente'
      });
    } else {
      // Login falló - mostrar error del servidor
      console.log('❌ Login falló:', data.message);
      displayResponse(data, true);
    }
  } catch (error) {
    // Error de comunicación con el servidor
    console.error('❌ Error durante login:', error);
    displayResponse({ 
      error: 'Error de comunicación con el servidor',
      details: 'Verifica que el servidor backend esté ejecutándose',
      hint: 'Asegúrate de que el servidor esté disponible en ' + API_BASE
    }, true);
  }
});

// ===================================================================================================
// 👤 EVENT LISTENER: BOTÓN OBTENER PERFIL
// ===================================================================================================

// Demuestra cómo acceder a un endpoint protegido con JWT
getProfileBtn.addEventListener('click', async () => {
  console.log('👤 Solicitando perfil de usuario...');
  
  try {
    // Realizar petición autenticada al endpoint de perfil
    const response = await fetchWithJWT(`${API_BASE}/profile`);
    const data = await response.json();
    
    if (response.ok) {
      console.log('✅ Perfil obtenido exitosamente');
      displayResponse({
        message: '✅ Perfil obtenido exitosamente',
        ...data,
        note: '🎫 Datos extraídos directamente del JWT payload sin consulta a base de datos'
      });
    } else {
      console.log('❌ Error obteniendo perfil:', data);
      displayResponse(data, true);
      
      // Si es error 401, intentar renovar token automáticamente
      if (response.status === 401) {
        console.log('🔄 Token expirado - iniciando renovación automática...');
        await checkAuthStatus();
      }
    }
  } catch (error) {
    console.error('❌ Error en petición de perfil:', error);
    displayResponse({ 
      error: 'Error conectando con el servidor',
      endpoint: '/api/profile'
    }, true);
  }
});

// ===================================================================================================
// 🔒 EVENT LISTENER: BOTÓN OBTENER DATOS SECRETOS
// ===================================================================================================

// Demuestra autorización basada en roles través de JWT
getSecretBtn.addEventListener('click', async () => {
  console.log('🔒 Solicitando datos secretos (basado en rol)...');
  
  try {
    // Petición a endpoint que requiere autenticación y verifica roles
    const response = await fetchWithJWT(`${API_BASE}/secret-data`);
    const data = await response.json();
    
    if (response.ok) {
      console.log('✅ Datos secretos obtenidos - rol verificado');
      displayResponse({
        message: '🔒 Datos secretos obtenidos exitosamente',
        ...data,
        note: '🎭 Contenido personalizado basado en el rol JWT del usuario'
      });
    } else {
      console.log('❌ Error obteniendo datos secretos:', data);
      displayResponse(data, true);
      
      // Manejar expiración de token
      if (response.status === 401) {
        await checkAuthStatus();
      }
    }
  } catch (error) {
    console.error('❌ Error obteniendo datos secretos:', error);
    displayResponse({ 
      error: 'Error conectando con el servidor',
      endpoint: '/api/secret-data'
    }, true);
  }
});

// ===================================================================================================
// 🔄 EVENT LISTENER: BOTÓN RENOVAR TOKEN
// ===================================================================================================

// Permite renovación manual del access token (normalmente es automática)
refreshTokenBtn.addEventListener('click', async () => {
  console.log('🔄 Renovación manual de token solicitada...');
  
  const success = await refreshAccessToken();
  
  if (success) {
    console.log('✅ Renovación manual exitosa');
    displayResponse({
      message: '🔄 Access token renovado exitosamente',
      note: '🎫 Nuevo token activo y listo para usar',
      validity: '15 minutos adicionales',
      autoRefresh: 'Configurado automáticamente'
    });
    
    // Actualizar estado de autenticación con nuevo token
    await checkAuthStatus();
  } else {
    console.log('❌ Renovación manual falló');
    displayResponse({
      error: '❌ No se pudo renovar el token',
      possibleCauses: [
        'Refresh token expirado (>7 días)',
        'Refresh token revocado en servidor',
        'Error de comunicación'
      ],
      hint: 'Intenta hacer login nuevamente'
    }, true);
    
    // Limpiar tokens inválidos y forzar login
    tokenManager.clearTokens();
    await checkAuthStatus();
  }
});

// ===================================================================================================
// 🚪 EVENT LISTENER: BOTÓN LOGOUT
// ===================================================================================================

// Maneja el proceso completo de cierre de sesión
logoutBtn.addEventListener('click', async () => {
  console.log('🚪 Iniciando proceso de logout...');
  
  const refreshToken = tokenManager.getRefreshToken();
  
  try {
    // Notificar al servidor para invalidar el refresh token
    // Esto previene el uso del token even si alguien lo obtuviera
    if (refreshToken) {
      console.log('📤 Notificando logout al servidor...');
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });
      console.log('✅ Servidor notificado - refresh token invalidado');
    }
    
    // Limpiar tokens del cliente
    tokenManager.clearTokens();
    
    // Actualizar interfaz al estado no autenticado
    await checkAuthStatus();
    
    console.log('🚪 Logout completado exitosamente');
    displayResponse({
      message: '🚪 Logout exitoso',
      actions: [
        '🗑️ Tokens eliminados del cliente',
        '❌ Refresh token invalidado en servidor',
        '🔓 Sesión cerrada completamente'
      ],
      note: 'El access token permanece técnicamente válido hasta su expiración natural (15 min) pero ya no es renovable'
    });
  } catch (error) {
    console.error('⚠️ Error comunicando logout al servidor:', error);
    
    // Aún así limpiar tokens localmente para seguridad
    tokenManager.clearTokens();
    await checkAuthStatus();
    
    displayResponse({
      message: '🚪 Logout local exitoso',
      warning: 'No se pudo notificar al servidor',
      note: 'Tokens eliminados localmente por seguridad'
    });
  }
});

// ===================================================================================================
// 🔄 EVENT LISTENER: BOTÓN ACTUALIZAR STORAGE
// ===================================================================================================

// Permite actualización manual del display de tokens
refreshStorageBtn.addEventListener('click', () => {
  console.log('🔄 Actualizando display de storage manualmente...');
  updateTokenDisplay();
  console.log('✅ Display actualizado');
});

// ===================================================================================================
// 🔍 EVENT LISTENER: BOTÓN DECODIFICAR JWT
// ===================================================================================================

// Herramienta educativa para decodificar y analizar tokens JWT
decodeJwtBtn.addEventListener('click', () => {
  console.log('🔍 Iniciando decodificación manual de JWT...');
  
  const token = jwtInput.value.trim();
  
  // Validar que se ingresó un token
  if (!token) {
    console.log('❌ No se ingresó token para decodificar');
    jwtOutput.innerHTML = `
<strong>⚠️ TOKEN REQUERIDO</strong>

Para usar esta herramienta:
1. Pega un token JWT en el campo de arriba
2. Presiona "Decodificar JWT"
3. Analiza la estructura y contenido

<strong>💡 FUENTES DE TOKENS:</strong>
- Copia tu token actual del storage
- Usa tokens de otros sistemas JWT
- Genera tokens de prueba online
    `;
    jwtOutput.className = 'info-box error';
    return;
  }
  
  try {
    // Decodificar el token ingresado
    const decoded = decodeJWT(token);
    const now = Math.floor(Date.now() / 1000);
    
    console.log('✅ Token decodificado exitosamente');
    
    // Mostrar análisis completo del token
    jwtOutput.innerHTML = `
<strong>🔍 JWT DECODIFICADO EXITOSAMENTE</strong>

<strong>📋 HEADER (Metadatos del Token):</strong>
${JSON.stringify(decoded.header, null, 2)}

<strong>📦 PAYLOAD (Datos del Usuario):</strong>
${JSON.stringify(decoded.payload, null, 2)}

<strong>🔐 SIGNATURE (Firma Digital):</strong>
${decoded.signature}
<em>Nota: La firma solo puede ser verificada por el servidor con la clave secreta</em>

<strong>⏰ ANÁLISIS TEMPORAL:</strong>
Emitido (iat): ${decoded.payload.iat ? new Date(decoded.payload.iat * 1000).toLocaleString() : 'No especificado'}
Expira (exp): ${decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toLocaleString() : 'No especificado'}
Estado actual: ${decoded.payload.exp && decoded.payload.exp < now ? '❌ EXPIRADO' : '✅ VÁLIDO (pero verificar firma en servidor)'}

<strong>🛡️ CONSIDERACIONES DE SEGURIDAD:</strong>
- Esta decodificación es solo para análisis
- La verificación de firma debe hacerse en el servidor
- Los datos pueden estar expuestos si el token es interceptado
- Usar HTTPS en producción es obligatorio
    `;
    jwtOutput.className = 'info-box success';
  } catch (error) {
    console.error('❌ Error decodificando token manual:', error);
    jwtOutput.innerHTML = `
<strong>❌ ERROR DE DECODIFICACIÓN</strong>

${error}

<strong>🔧 POSIBLES CAUSAS:</strong>
- Token malformado (debe tener formato: header.payload.signature)
- Caracteres inválidos o codificación incorrecta
- Token truncado o incompleto
- No es un JWT válido

<strong>💡 CONSEJOS:</strong>
- Verifica que copiaste el token completo
- Asegúrate de no incluir espacios extra
- Tokens JWT válidos tienen exactamente 2 puntos (.)
    `;
    jwtOutput.className = 'info-box error';
  }
});

// ===================================================================================================
// 🚀 INICIALIZACIÓN DE LA APLICACIÓN
// ===================================================================================================

// Función de inicialización que se ejecuta cuando la página carga
console.log('🚀 Iniciando aplicación JWT Frontend...');
console.log('🔧 Configurando estado inicial...');

// Verificar estado de autenticación inicial
// Esto permite que usuarios con tokens válidos permanezcan logueados
// aunque recarguen la página
checkAuthStatus();

// Inicializar display de tokens
updateTokenDisplay();

// ===================================================================================================
// ⏰ AUTO-ACTUALIZACIÓN PERIÓDICA
// ===================================================================================================

// Configurar actualización automática del display cada 5 segundos
// Esto mantiene la información de expiración actualizada en tiempo real
console.log('⏰ Configurando auto-actualización cada 5 segundos...');
setInterval(() => {
  updateTokenDisplay();
  console.log('🔄 Auto-actualización ejecutada');
}, 5000);

console.log('✅ Aplicación JWT Frontend inicializada completamente');
console.log('🎯 Lista para manejar autenticación JWT con tokens de doble capa');