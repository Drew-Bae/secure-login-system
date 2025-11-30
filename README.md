# Secure Login System (SLS)

A portfolio-grade secure authentication platform built to demonstrate real-world security controls and detection techniques.  
This project starts with a fully working login system and progressively adds advanced defenses like MFA, suspicious login detection, and an admin security console.

## Live Demo
- Frontend: https://secure-login-system-delta.vercel.app/
- API Health Check: https://secure-login-system-zhsn.onrender.com

## Current Features (v1.0)
- [x] Repo + monorepo structure initialized
- [x] Backend / Frontend / Docs folders created
- [x] MongoDB connection with Mongoose
- [x] User registration with bcrypt password hashing
- [x] Login with JWT issued into HttpOnly cookie
- [x] Logout endpoint clearing auth cookie
- [x] LoginAttempt logging (IP, user agent, success/fail)
- [x] Deployed API (Render) and frontend (Vercel)
- [ ] Basic admin view for login attempts (Phase 1.1)

## Roadmap
**Phase 1 — Working MVP (Deployable)**
- Register / Login / Logout
- bcrypt password hashing
- JWT stored in HttpOnly cookies
- CORS + secure cookie handling
- Rate limiting (to be added)
- Deployed frontend (Vercel)
- Deployed API (Render)

**Phase 2 — Hardened Auth**
- Email verification
- Forgot / Reset password
- MFA (TOTP or email codes)
- Account lockout + cooldown
- Device tracking

**Phase 3 — Suspicious Login Detection**
- New IP / new device detection
- Impossible travel heuristic (geo-based)
- Risk scoring system
- Step-up authentication when risk is high
- User-visible login history

**Phase 4 — Admin Security Console**
- View users & login attempts
- Flag high-risk accounts
- Lock/unlock accounts
- Force password reset
- Export audit logs (CSV / JSON)

## Security Decisions (Why this matters)
- **bcrypt hashing** Protects credentials even if the database is compromised.
- **HttpOnly JWT cookies** Prevent token theft via XSS.
- **Session-like JWT strategy** Simplifies frontend logic while maintaing secure cookie boundaries.
- **Rate limiting (upcoming)** Stops brute-force and credential-stuffing attempts.
- **Audit logging (AuditAttempt model)** Essential for detection, incident response, and risk scoring.
- **Suspicious login detection (upcoming)** Models modern Zero Trust logic by evaluating context, not just credentials.

## Tech Stack (v1)
- Frontend: React
- Backend: Node.js + Express
- Database: MongoDB + Mongoose
- Auth: JWT (HttpOnly cookies)
- Email: Zoho SMTP (Phase 2)
- Deployment: 
    - Backend: Render
    - Frontend: Vercel

## Getting Started 
Detailed setup instructions will be added after Phase 1 deployment.
For now, the project runs with:

### Backend
```arduino
cd backend
npm install
npm run dev
```

### Frontend
```powershell
cd frontend
npm install
npm start
```