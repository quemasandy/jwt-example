# 🎫 JWT Authentication Demo - Proyecto Educativo Completo

[![Security: Demo Only](https://img.shields.io/badge/Security-Demo%20Only-yellow.svg)](./SECURITY.md)
[![License: Educational](https://img.shields.io/badge/License-Educational-blue.svg)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?logo=typescript&logoColor=white)](#)
[![Node.js](https://img.shields.io/badge/Node.js-43853D?logo=node.js&logoColor=white)](#)

Una implementación completa y educativa de autenticación JWT con backend Node.js/Express y frontend TypeScript/Vite. Diseñado específicamente para enseñar conceptos de autenticación moderna.

## 🎯 ¿Qué Aprenderás?

- **Autenticación JWT** con tokens de acceso y renovación
- **Seguridad web** y mejores prácticas
- **Arquitectura cliente-servidor** moderna
- **Gestión de estado** en aplicaciones web
- **Control de acceso basado en roles** (RBAC)

## 🏗️ Arquitectura del Sistema

```
┌─────────────────┐    HTTP/JSON    ┌─────────────────┐
│   Frontend      │ ◄─────────────► │    Backend      │
│                 │                 │                 │
│ • TypeScript    │                 │ • Node.js       │
│ • Vite          │                 │ • Express       │
│ • JWT Decoder   │                 │ • jsonwebtoken  │
│ • Token Manager │                 │ • CORS          │
└─────────────────┘                 └─────────────────┘
        │                                   │
        ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐
│  localStorage   │                 │   Memory Store  │
│  (Persistencia) │                 │ (Refresh Tokens)│
└─────────────────┘                 └─────────────────┘
```

## 🚀 Inicio Rápido

### 1. **Configuración del Proyecto**

```bash
# Clonar el repositorio
git clone <tu-repo-url>
cd jwt-example

# Configurar variables de entorno
cp .env.example .env
# Edita .env con tus valores (o usa los por defecto para desarrollo)
```

### 2. **Instalar Dependencias**

```bash
# Backend
cd backend
npm install

# Frontend (en otra terminal)
cd frontend
npm install
```

### 3. **Ejecutar la Aplicación**

```bash
# Terminal 1: Backend (Puerto 3000)
cd backend
npm run dev

# Terminal 2: Frontend (Puerto 5173)
cd frontend
npm run dev
```

### 4. **Acceder a la Aplicación**

- **Frontend:** http://localhost:5173
- **API Backend:** http://localhost:3000/api

## 📚 Guía de Aprendizaje para Estudiantes

### 🎯 **Nivel 1: Conceptos Básicos (30-45 min)**

#### **Ejercicio 1: Entender la Estructura JWT**
1. Abre la aplicación en el navegador
2. Ve a la sección **"Decodificador JWT"**
3. **Prueba esto:**
   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
   ```
4. **Observa:** ¿Qué información contiene cada parte?
5. **Reflexiona:** ¿Por qué hay 3 partes separadas por puntos?

#### **Ejercicio 2: Proceso de Login**
1. Usa estas credenciales de prueba:
   - **Usuario:** `demo_user` | **Contraseña:** `demo123`
   - **Usuario:** `demo_admin` | **Contraseña:** `admin456`
2. **Observa en la consola del navegador** (F12) los logs durante el login
3. **Pregúntate:**
   - ¿Qué tokens se recibieron?
   - ¿Dónde se almacenan?
   - ¿Cuál es la diferencia entre access y refresh token?

#### **Ejercicio 3: Inspeccionar Tokens en Vivo**
1. Después del login, copia el **access token** del monitor de almacenamiento
2. Pégalo en el decodificador JWT
3. **Analiza:**
   - `iat`: ¿Cuándo se emitió?
   - `exp`: ¿Cuándo expira?
   - `userId`, `username`, `role`: Información del usuario

### 🎯 **Nivel 2: Flujos de Autenticación (45-60 min)**

#### **Ejercicio 4: Probar Autorización por Roles**
1. Inicia sesión con diferentes usuarios:
   - `demo_user` (rol: user)
   - `demo_admin` (rol: admin)  
   - `demo_super` (rol: superadmin)
2. Haz clic en **"Datos Secretos"** con cada usuario
3. **Compara las respuestas:** ¿Qué datos ve cada rol?

#### **Ejercicio 5: Expiración y Renovación de Tokens**
1. Modifica `backend/src/server.ts` línea ~140:
   ```typescript
   expiresIn: '30s' // Cambiar de '15m' a '30s'
   ```
2. Reinicia el backend
3. Inicia sesión y **espera 30 segundos**
4. Intenta hacer una petición (ej: "Ver Mi Perfil")
5. **Observa:** ¿Se renovó automáticamente el token?

#### **Ejercicio 6: Comportamiento de Logout**
1. Inicia sesión normalmente
2. Copia el **refresh token** antes de hacer logout
3. Haz logout
4. En la consola del navegador, intenta usar el refresh token copiado:
   ```javascript
   fetch('http://localhost:3000/api/refresh', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({ refreshToken: 'PEGA_AQUI_EL_TOKEN' })
   }).then(r => r.json()).then(console.log)
   ```
5. **Resultado esperado:** Error, el token fue invalidado

### 🎯 **Nivel 3: Análisis de Seguridad (60-90 min)**

#### **Ejercicio 7: Manipulación de Tokens**
1. Inicia sesión como `demo_user`
2. En la consola, obtén el access token:
   ```javascript
   localStorage.getItem('accessToken')
   ```
3. Decodifica el token y **cambia manualmente** el rol de 'user' a 'admin'
4. Intenta usar este token modificado
5. **¿Qué sucede?** ¿Por qué falla la verificación?

#### **Ejercicio 8: Explorar Almacenamiento**
1. Con la aplicación abierta, ve a **DevTools → Application → Local Storage**
2. **Inspecciona:** ¿Qué tokens están almacenados?
3. **Borra manualmente** solo el accessToken
4. Recarga la página
5. **Observa:** ¿Cómo recupera la sesión?

#### **Ejercicio 9: Interceptar Peticiones HTTP**
1. Abre **DevTools → Network**
2. Haz algunas peticiones (perfil, datos secretos)
3. **Examina los headers:**
   - ¿Dónde va el token JWT?
   - ¿Qué formato tiene el header Authorization?
4. **Busca:** ¿Se envían los tokens en URLs o cookies?

### 🎯 **Nivel 4: Modificación y Experimentación (90+ min)**

#### **Ejercicio 10: Cambiar Tiempos de Expiración**
1. Modifica los tiempos en `backend/src/server.ts`:
   ```typescript
   // Línea ~140: Access token
   expiresIn: '5m'
   
   // Línea ~154: Refresh token  
   expiresIn: '1h'
   ```
2. **Prueba:** ¿Cómo afecta esto a la experiencia de usuario?

#### **Ejercicio 11: Agregar Nuevo Endpoint Protegido**
1. En `backend/src/server.ts`, agrega después de línea ~900:
   ```typescript
   // Endpoint solo para superadmins
   app.get('/api/admin-only', authenticateToken, (req: any, res) => {
     if (req.user.role !== 'superadmin') {
       return res.status(403).json({ error: 'Solo superadmins' });
     }
     res.json({ 
       message: 'Datos ultra secretos',
       data: ['config1', 'config2', 'config3']
     });
   });
   ```
2. En el frontend, agrega un botón para probar este endpoint
3. **Verifica:** ¿Solo los superadmins pueden acceder?

#### **Ejercicio 12: Implementar Rate Limiting Básico**
1. Instala express-rate-limit:
   ```bash
   cd backend && npm install express-rate-limit
   ```
2. Agrégalo al login endpoint:
   ```typescript
   import rateLimit from 'express-rate-limit';
   
   const loginLimiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutos
     max: 5, // máximo 5 intentos
     message: 'Demasiados intentos de login'
   });
   
   app.post('/api/login', loginLimiter, (req, res) => {
     // código existente...
   });
   ```
3. **Prueba:** Intenta hacer login 6 veces seguidas con credenciales incorrectas

### 🎯 **Nivel 5: Análisis de Código Avanzado**

#### **Ejercicio 13: Seguir el Flujo de Tokens**
1. **Lee el código** de `frontend/src/app.ts` líneas 200-300
2. **Identifica:** ¿Cómo funciona la renovación automática?
3. **Encuentra:** La función `fetchWithJWT()` - ¿qué hace cuando un token expira?

#### **Ejercicio 14: Explorar Middleware de Autenticación**
1. **Estudia** `backend/src/server.ts` líneas 180-220
2. **Entiende:** ¿Cómo verifica el servidor cada token?
3. **Modifica:** Agrega logging para ver cada verificación:
   ```typescript
   console.log(`Token verificado para usuario: ${decoded.username}`);
   ```

#### **Ejercicio 15: Comparar Estrategias de Almacenamiento**
1. **Experimenta** comentando líneas 78-79 en `frontend/src/app.ts`:
   ```typescript
   // localStorage.setItem('accessToken', accessToken);
   // localStorage.setItem('refreshToken', refreshToken);
   ```
2. **Observa:** ¿Qué pasa al recargar la página?
3. **Reflexiona:** ¿Cuáles son los trade-offs de cada estrategia?

## 🔍 Preguntas de Reflexión para Estudiantes

### **Seguridad**
- ¿Por qué usamos tokens separados (access + refresh)?
- ¿Qué riesgos tiene almacenar JWTs en localStorage?
- ¿Cómo se podría mejorar la seguridad en producción?

### **Arquitectura**
- ¿Por qué el servidor no mantiene estado de sesiones?
- ¿Cómo escalaría esta solución con millones de usuarios?
- ¿Qué alternativas existen a JWT?

### **Experiencia de Usuario**
- ¿Cómo afectan los tiempos de expiración a la UX?
- ¿Qué pasa si el usuario tiene múltiples pestañas abiertas?
- ¿Cómo manejar la renovación de tokens en segundo plano?

## 📖 Conceptos Clave Cubiertos

### **JWT (JSON Web Tokens)**
- Estructura: Header.Payload.Signature
- Algoritmos de firmado (HS256)
- Claims estándar (iat, exp, sub)

### **Autenticación vs Autorización**
- Login y verificación de identidad
- Control de acceso basado en roles (RBAC)
- Principio de menor privilegio

### **Gestión de Estado**
- Almacenamiento dual (memoria + persistencia)
- Sincronización entre pestañas
- Manejo de expiración

### **Seguridad Web**
- CORS (Cross-Origin Resource Sharing)
- HTTPS y transporte seguro
- Validación de entrada
- Principios de defensa en profundidad

## 🛡️ Consideraciones de Seguridad

⚠️ **IMPORTANTE:** Este es un proyecto educativo. Ver [SECURITY.md](./SECURITY.md) para consideraciones de producción.

### **Limitaciones Actuales:**
- Usuarios de demostración con contraseñas simples
- Almacenamiento de tokens en memoria/localStorage
- Secretos JWT con valores por defecto

### **Para Producción:**
- Usar HTTPS obligatorio
- Implementar rate limiting
- Hashear contraseñas con bcrypt
- Usar cookies HttpOnly para tokens
- Implementar CSP y headers de seguridad

## 📚 Recursos Adicionales

### **Documentación**
- [JWT.io](https://jwt.io/) - Decodificador y guías
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - Especificación JWT
- [OWASP JWT Guide](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### **Herramientas**
- [JWT Debugger](https://jwt.io/#debugger-io)
- [Postman](https://www.postman.com/) - Para probar APIs
- [Browser DevTools](https://developer.chrome.com/docs/devtools/) - Network y Application tabs

## 🤝 Contribuciones

Este proyecto es educativo. Las contribuciones que mejoren el valor didáctico son bienvenidas:

- Ejercicios adicionales
- Mejores explicaciones
- Ejemplos de seguridad
- Documentación más clara

## 📄 Licencia

Proyecto educativo de código abierto. Libre para uso en contextos académicos y de aprendizaje.

---

**Happy Learning! 🎓** ¿Tienes preguntas? Abre un issue o revisa los comentarios detallados en el código.