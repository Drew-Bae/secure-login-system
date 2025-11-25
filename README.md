# Secure Login System (SLS)

A portfolio-grade secure authentication platform built to demonstrate real-world security controls and detection techniques.  
This project starts with a fully working login system and progressively adds advanced defenses like MFA, suspicious login detection, and an admin security console.

## Live Demo
🚧 Coming soon (Phase 1).  
Once deployed, the latest stable build will always be hosted here.

## Current Features (v0.1)
- [x] Repo + monorepo structure initialized
- [x] Backend / Frontend / Docs folders created
- [ ] Working Register / Login / Logout (Phase 1)
- [ ] Password hashing + secure cookie auth (Phase 1)
- [ ] Login attempt logging (Phase 1)
- [ ] Basic suspicious login flagging (Phase 1)

## Roadmap
**Phase 1 — Working MVP (Deployable)**
- Register / Login / Logout
- bcrypt password hashing
- JWT stored in HttpOnly cookies
- Rate limiting + basic validation
- Deployed demo link

**Phase 2 — Hardened Auth**
- Email verification
- Forgot / Reset password
- MFA (TOTP or email codes)
- Account lockout + cooldown

**Phase 3 — Suspicious Login Detection**
- New IP / new device detection
- Impossible travel heuristic
- Risk scoring + step-up auth
- User-visible login history

**Phase 4 — Admin Security Console**
- View/flag users & attempts
- Lock/unlock accounts
- Force password reset
- Export audit logs

## Security Decisions (Why this matters)
- **bcrypt hashing** prevents plaintext password compromise.
- **HttpOnly cookie JWTs** reduce XSS token theft risk.
- **Rate limiting + lockout** mitigates brute-force attacks.
- **Audit logging** supports detection and incident response.
- **Risk scoring & step-up auth** models modern Zero Trust logins.

## Tech Stack (v1)
- Frontend: React
- Backend: Node.js + Express
- Database: MongoDB + Mongoose
- Auth: JWT (HttpOnly cookies)
- Email: Zoho SMTP (Phase 2)
- Deployment: Render + Vercel (Phase 1)

## Getting Started (will update as we build)
Phase 1 will add runnable backend and frontend instructions.
