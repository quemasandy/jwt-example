# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a JWT authentication demo with a Node.js/Express backend and TypeScript/Vite frontend. The backend implements a dual-token system (access + refresh tokens) with role-based access control, while the frontend provides a comprehensive JWT management interface.

## Development Commands

### Backend (Node.js/Express)
```bash
cd backend
npm install
npm run dev     # Start development server with hot reload (nodemon)
npm run build   # Compile TypeScript to dist/
npm start       # Run compiled JavaScript
```

### Frontend (TypeScript/Vite)
```bash
cd frontend
npm install
npm run dev     # Start Vite dev server
npm run build   # Build for production
npm run preview # Preview production build
```

## Architecture

### JWT Token System
- **Access Tokens**: 15-minute expiry, contain user data (userId, username, role)
- **Refresh Tokens**: 7-day expiry, used for token renewal
- **Dual Secrets**: Separate signing keys for each token type

### Backend Structure (backend/src/server.ts)
- **Token Creation**: `createAccessToken()` and `createRefreshToken()` functions
- **Auth Middleware**: `authenticateToken()` validates Bearer tokens
- **API Endpoints**:
  - `POST /api/login` - User authentication
  - `GET /api/profile` - Protected user profile
  - `POST /api/refresh` - Token renewal
  - `POST /api/logout` - Token invalidation
  - `GET /api/secret-data` - Role-based content

### Frontend Structure (frontend/src/app.ts)
- **TokenManager Class**: Handles token storage and lifecycle
- **fetchWithJWT()**: Automatic token inclusion in requests
- **JWT Decoder**: Client-side token inspection without verification
- **Auto-refresh**: Transparent token renewal on expiration

### Authentication Flow
1. Login returns both access and refresh tokens
2. Frontend stores tokens (memory + localStorage)
3. API requests include `Authorization: Bearer <token>` header
4. Expired access tokens trigger automatic refresh
5. Failed refresh redirects to login

## Key Implementation Details

- **Backend**: CommonJS modules, compiled to dist/
- **Frontend**: ESNext modules, Vite bundling
- **CORS**: Configured for localhost:5173 (frontend origin)
- **Error Handling**: Comprehensive JWT validation and user feedback
- **Token Storage**: In-memory array for refresh tokens (demo only)
- **Role System**: user/admin/superadmin roles with different data access

## Security Notes

- JWT secrets are hardcoded (use environment variables in production)
- Refresh tokens stored in memory (use Redis/database in production)
- Demo includes pre-configured test users
- Spanish comments throughout backend code for documentation