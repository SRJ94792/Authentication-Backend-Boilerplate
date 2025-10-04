# Node.js Authentication Backend Boilerplate

A production-ready authentication backend for Node.js/Express with:

- User Registration with email verification
- User Login with JWT access tokens
- Password Management (change, forgot/reset)
- Email Verification via signed tokens
- Token Management with refresh tokens and rotation
- Role-Based Access Control (RBAC) with Admin, Project Admin, and Member roles

This README documents how to configure, run, and use the API.

## Tech Highlights

- Node.js + Express
- JSON Web Tokens (JWT) for stateless auth
- Refresh token rotation and invalidation
- Email delivery via SMTP (Nodemailer compatible)
- Pluggable database via `DATABASE_URL` (use your ORM/driver of choice)
- Optional hardening: Helmet, CORS, rate limiting
- Designed to integrate with browsers (httpOnly refresh cookie) and mobile/CLI clients (header-based refresh)

## Prerequisites

- Node.js >= 18 LTS
- npm / yarn / pnpm
- A database (e.g., PostgreSQL, MySQL, MongoDB) reachable via `DATABASE_URL`
- SMTP provider (e.g., Mailtrap, SendGrid, SES) for email verification and password reset

## Getting Started

1) Install dependencies

```bash
npm install
# or
yarn install
# or
pnpm install
```

2) Create your environment file `.env`

```bash
# Server
PORT=4000
NODE_ENV=development
APP_URL=http://localhost:4000
CLIENT_URL=http://localhost:5173
CORS_ORIGIN=http://localhost:5173

# Database
DATABASE_URL=postgres://user:password@localhost:5432/yourdb

# JWT
JWT_ACCESS_SECRET=replace-with-strong-random-string
JWT_REFRESH_SECRET=replace-with-strong-random-string
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=7d

# Email (SMTP)
EMAIL_FROM="Your App <no-reply@yourapp.com>"
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_smtp_user
SMTP_PASS=your_smtp_pass

# Token TTLs
EMAIL_TOKEN_TTL=24h
RESET_TOKEN_TTL=1h
```

Notes:
- ACCESS_TOKEN_TTL and REFRESH_TOKEN_TTL can be any `ms`-style durations (e.g., `15m`, `7d`).
- For local dev, use Mailtrap or a similar tool for SMTP.

3) Run the server

```bash
# Development (watch mode)
npm run dev

# Production build + start (if applicable)
npm run build && npm start

# Or run directly
node ./src/server.js
```

Adjust commands to match your scripts and file layout.

## Authentication Overview

- Access Token: short-lived JWT used in the `Authorization` header.
  - Header: `Authorization: Bearer <access_token>`
- Refresh Token: long-lived token for obtaining new access tokens.
  - Recommended default: httpOnly, Secure cookie `refresh_token`
  - Alternative: send/receive via `Authorization: Refresh <refresh_token>` or request body
- Email verification and password reset are handled via time-bound signed tokens emailed to the user.

### Roles

- Admin: Full access to administrative endpoints
- Project Admin: Elevated permissions scoped to project resources
- Member: Default role for standard users

## API Endpoints

Base URL: `${APP_URL}` (e.g., `http://localhost:4000`)

### Auth

- POST `/api/auth/register`
  - Description: Create account and send verification email
  - Body:
    ```json
    {
      "email": "user@example.com",
      "password": "StrongP@ssw0rd!",
      "name": "Jane Doe"
    }
    ```
  - Response: 201 Created
    ```json
    {
      "message": "Registration successful. Please verify your email.",
      "userId": "uuid-or-id"
    }
    ```

- GET `/api/auth/verify-email?token=...`
  - Description: Verify account via token sent to email
  - Response: 200 OK
    ```json
    { "message": "Email verified successfully" }
    ```

- POST `/api/auth/resend-verification`
  - Body:
    ```json
    { "email": "user@example.com" }
    ```
  - Response: 200 OK

- POST `/api/auth/login`
  - Description: Authenticate user, issue access token and refresh token
  - Body:
    ```json
    {
      "email": "user@example.com",
      "password": "StrongP@ssw0rd!"
    }
    ```
  - Response: 200 OK
    - Set-Cookie: `refresh_token` httpOnly (if cookie mode enabled)
    - Body:
      ```json
      {
        "accessToken": "<jwt>",
        "user": {
          "id": "uuid-or-id",
          "email": "user@example.com",
          "role": "Member"
        }
      }
      ```

- POST `/api/auth/refresh-token`
  - Description: Rotate/issue new access token (and optionally refresh token)
  - Auth: via httpOnly cookie or header/body depending on configuration
  - Response: 200 OK
    ```json
    { "accessToken": "<new-jwt>" }
    ```

- POST `/api/auth/logout`
  - Description: Invalidate refresh token (e.g., remove server-side session/rotate token)
  - Response: 204 No Content

### Passwords

- POST `/api/auth/forgot-password`
  - Body:
    ```json
    { "email": "user@example.com" }
    ```
  - Response: 200 OK

- POST `/api/auth/reset-password`
  - Description: Reset password with token sent to email
  - Body:
    ```json
    {
      "token": "<reset-token>",
      "password": "NewStrongP@ssw0rd!"
    }
    ```
  - Response: 200 OK

- POST `/api/auth/change-password`
  - Description: Change password for logged-in user
  - Auth: Bearer access token
  - Body:
    ```json
    {
      "currentPassword": "OldP@ssw0rd!",
      "newPassword": "NewStrongP@ssw0rd!"
    }
    ```
  - Response: 200 OK

### User

- GET `/api/users/me`
  - Description: Get current user profile
  - Auth: Bearer access token
  - Response:
    ```json
    {
      "id": "uuid-or-id",
      "email": "user@example.com",
      "name": "Jane Doe",
      "role": "Member",
      "emailVerified": true
    }
    ```

### Admin (RBAC)

- GET `/api/admin/users`
  - Description: List users
  - Auth: Admin role

- PATCH `/api/admin/users/:id/role`
  - Description: Update a user's role to `Admin`, `ProjectAdmin`, or `Member`
  - Auth: Admin role
  - Body:
    ```json
    { "role": "ProjectAdmin" }
    ```

- Example project-scoped routes (RBAC example only):
  - GET `/api/projects/:id` (Member+)
  - POST `/api/projects` (ProjectAdmin+)
  - DELETE `/api/projects/:id` (Admin)

## Request/Response Conventions

- Authenticated routes require `Authorization: Bearer <access_token>`
- JSON responses use a consistent error shape, e.g.:
  ```json
  {
    "error": {
      "code": "VALIDATION_ERROR",
      "message": "Email is required",
      "details": [ /* optional field-level details */ ]
    }
  }
  ```

## Implementation Notes & Best Practices

- Hash passwords with bcrypt or argon2
- Store refresh tokens server-side (e.g., token store or allow-list) to support invalidation
- Rotate refresh tokens on each refresh to limit replay risk
- Use httpOnly, Secure cookies for refresh tokens in browsers; set `SameSite` appropriately
- Rate-limit login, register, forgot-password endpoints
- Enforce strong password policy and input validation
- Use Helmet and strict CORS configuration
- Log security-relevant events (login attempts, token refresh, role changes)

## Suggested Project Structure

```
src/
  config/
  middleware/
  modules/
    auth/
      auth.controller.ts|js
      auth.routes.ts|js
      auth.service.ts|js
      auth.validators.ts|js
    users/
      users.controller.ts|js
      users.routes.ts|js
      users.service.ts|js
    roles/
      rbac.middleware.ts|js
  utils/
  server.ts|js
```

Adapt as needed for your framework (Express/Fastify) and language (JS/TS).

## Environment & Security Checklist

- Use distinct secrets for access vs. refresh JWTs
- Keep secrets out of source control; use environment variables or a secret manager
- Set `NODE_ENV=production` in production
- Enable HTTPS in production so cookies are transmitted securely
- Monitor and rotate secrets periodically

## Troubleshooting

- Email not sending: verify SMTP settings and network access
- 401 Unauthorized: ensure the `Authorization` header is present and not expired
- 403 Forbidden: user role may not have permission for the endpoint
- Token refresh failing: confirm refresh token cookie/header is being sent and not revoked/expired

