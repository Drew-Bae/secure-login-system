# SLS API Reference (High-level)

Base path: `/api`

## Auth model
- Session uses a JWT stored in an HttpOnly cookie: `token`
- Most state-changing routes require a CSRF header (double-submit pattern)

## CSRF
Before POST/PUT/PATCH/DELETE:
1) `GET /api/auth/csrf`
2) Send header: `X-CSRF-Token: <value>`

The frontend automatically handles this via Axios interceptors.

## Device ID tracking
Requests include:
- Header: `x-device-id`
- Stored in browser localStorage: `sls_device_id`

---

# Auth
## GET /api/auth/csrf
Returns a CSRF token (and sets csrf cookie on API origin).

## POST /api/auth/register
Body: `{ "email": "...", "password": "..." }`

## POST /api/auth/resend-verification
Body: `{ "email": "..." }`

## GET /api/auth/verify-email?token=...
Verifies the email token.

## POST /api/auth/login
Body: `{ "email": "...", "password": "..." }`

Possible responses:
- Success: issues cookie and returns `{ message, riskScore, highRisk, reasons }`
- Step-up email required: `{ stepUpRequired: true, preAuthToken, risk }`
- MFA required: `{ mfaRequired: true, preAuthToken, risk }`
- Blocked high-risk: `403 { actionRequired: "ENABLE_MFA", riskScore, reasons }`
- Unverified: `403 { actionRequired: "VERIFY_EMAIL" }`
- Forced reset: `403 { actionRequired: "FORCE_PASSWORD_RESET" }`

## POST /api/auth/stepup-email
Body: `{ "preAuthToken": "...", "risk": {...} }`
Sends a one-time step-up verification email.

## POST /api/auth/verify-stepup
Body: `{ "token": "...", "preAuthToken": "..." }`
If valid, issues the auth cookie.

## POST /api/auth/mfa-login
Body: `{ "preAuthToken": "...", "code": "123456" }`
If valid, issues the auth cookie.

## POST /api/auth/logout
Clears auth cookie.

## POST /api/auth/logout-all
Revokes all sessions (tokenVersion++) and clears auth cookie.

## GET /api/auth/me
Returns current user.

## GET /api/auth/login-history
Returns user-visible login attempts list.

## POST /api/auth/forgot-password
Body: `{ "email": "..." }`

## POST /api/auth/reset-password
Body: `{ "token": "...", "password": "..." }`

## POST /api/auth/change-password (optional if implemented)
Body: `{ "currentPassword": "...", "newPassword": "..." }`
Changes password + revokes sessions.

---

# MFA
## POST /api/mfa/setup
Returns secret/otpauth URL/QR data.

## POST /api/mfa/verify
Body: `{ "code": "123456" }`
Enables MFA if code valid.

---

# Devices (User)
## GET /api/devices
Lists device records for the authenticated user.

## POST /api/devices/:deviceId/trust
Marks device as trusted.

## POST /api/devices/:deviceId/revoke
Revokes sessions for that device (tokenVersion++).

## POST /api/devices/:deviceId/compromised
Body: `{ "reason": "lost_device" }`
Marks compromised + sets trusted=false + revokes sessions.

---

# Admin (requires admin role)
## GET /api/admin/login-attempts
Supports filters via query params:
- email, ip, success, country, deviceId
- minRisk, maxRisk
- from, to (date range)
- page, limit
- onlySuspicious

## GET /api/admin/users
Supports filters like email/locked/etc (see implementation)

## GET /api/admin/users/:id
User detail

## POST /api/admin/users/:id/lock
Body: `{ "minutes": 60 }`

## POST /api/admin/users/:id/unlock

## POST /api/admin/users/:id/revoke-sessions

## POST /api/admin/users/:id/force-password-reset
Body: `{ "reason": "...", "sendEmail": true }`

## POST /api/admin/users/:id/note
Body: `{ "note": "..." }`

## GET /api/admin/audit
Audit log feed

## GET /api/admin/audit/export.json
## GET /api/admin/audit/export.csv

## GET /api/admin/blocked-ips
## POST /api/admin/blocked-ips
Body: `{ "ip": "...", "minutes": 60, "reason": "..." }`

## DELETE /api/admin/blocked-ips/:id

## POST /api/admin/devices/:deviceRecordId/compromised
Admin override to set compromised true/false
