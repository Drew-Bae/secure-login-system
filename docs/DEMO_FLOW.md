# SLS Demo Flow (Reviewer Guide)

This doc walks a reviewer through the “wow” parts of the Secure Login System.

## Quick start (local)
- Start: `docker compose up`
- Frontend: http://localhost:3000
- Backend: http://localhost:5000

## Notes about how SLS tracks “device”
SLS assigns a device ID in the browser and sends it on every request:
- Stored in localStorage: `sls_device_id`
- Sent as header: `x-device-id`

To simulate a **new device**:
- Open an incognito window, OR
- Clear `localStorage.sls_device_id`

To simulate a **new IP**:
- Use a VPN, mobile hotspot, or different network.

---

## Flow A — Normal registration + verification + login
1) Go to `/register`
2) Register with an email/password
3) Verify email:
   - In local dev, check logs or your email provider (depending on env)
   - Or use `/verify-email` page if your UI supports it
4) Login at `/login`
5) Visit `/security` to see login history and risk signals.

---

## Flow B — Suspicious login → Step-up (Email) or MFA (TOTP)
Goal: show risk scoring + step-up before issuing a session cookie.

1) Trigger risk (any one works):
   - New device: clear `localStorage.sls_device_id` then login again
   - New IP: login from another network/VPN
   - Multiple failed attempts: intentionally fail login a few times

2) Login response will require step-up:
   - If MFA enabled: `mfaRequired: true` (TOTP)
   - Otherwise: `stepUpRequired: true` and method `email`

3) Complete step-up:
   - Email method: request a step-up email and verify the token
   - MFA method: enter a valid TOTP code

4) Confirm you land authenticated and can access `/security`.

---

## Flow C — Account protections
### 1) Lockout / cooldown
- Attempt multiple failed logins
- Confirm lockout behavior (blocked temporarily)
- Confirm admin can unlock later

### 2) Forced password reset (Admin action)
- As admin, force a user to reset password
- User attempts to login
- They receive: `actionRequired: FORCE_PASSWORD_RESET`
- Complete reset via `/forgot-password` / `/reset-password`

---

## Flow D — Device management
1) Go to `/devices`
2) Trust a device
3) Revoke a device (logs that device out but may remain “trusted”)
4) Mark compromised:
   - Should revoke + set trusted=false
   - Should display compromised date + reason in UI

---

## Flow E — Admin Console (security operations)
Login as admin and show:
- Login Attempts view with filters (email/ip/success/risk range)
- Users list + user detail
- Lock/unlock
- Revoke sessions
- Force reset password
- Audit log (and export if enabled)
- Blocked IP management
