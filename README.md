# Secure Login System (SLS)

A portfolio-grade secure authentication platform built to demonstrate real-world security controls and detection techniques.  
This project starts with a fully working login system and progressively adds advanced defenses like MFA, suspicious login detection, and an admin security console.

## Live Demo
- Frontend: https://secure-login-system-delta.vercel.app/
- API Health Check (open first and make sure it is running): https://secure-login-system-zhsn.onrender.com

The live demo includes working registration, login, logout, secure HttpOnly cookie handling, login attempt logging, basic suspicious login detection, and an admin view for recent login activity.
### **🔐 Demo Admin Account (for testing the Admin Dashboard)**
A temporary admin user is provided so reviewers can access the admin dashboard and inspect suspicious login activity. The admin account exists solely for demonstration purposes and has limited access. No sensitive data is stored:
```makefile
Email: admin@example.com  
Password: pass123
```
This account allows access to:
- Recent login attempts
- Suspicious activity flags
- IP and User-Agent metadata
- Detection reasons (multiple failures, new IP, etc.)

## Current Features (v3.0 - In Progress)
### **Advanced Suspicious Login Detection**
- More advanced heuristics (geo-based “impossible travel”)  
- IP reputation and ASN considerations  
- Risk scoring system  
- Step-up authentication when risk is high  
- User-visible login history  

## Roadmap

**Phase 1 — Working MVP (Deployable)**  
- Register / Login / Logout  
- bcrypt password hashing  
- JWT stored in HttpOnly cookies  
- CORS + secure cookie handling  
- Frontend hooked to backend (Register & Login pages)  
- LoginAttempt logging (IP, user agent, success/fail)  
- Basic suspicious login heuristics (multiple failures, new IP)  
- Admin API to query login attempts  
- Admin UI to view login attempts  
- Deployment:
  - Frontend on Vercel  
  - API on Render  
- Live demo links added to README  
- Rate limiting (to be added next in Phase 1.x)  

**Phase 2 — Hardened Auth**  
- Email verification  
- Forgot / Reset password  
- MFA (TOTP or email codes)  
- Account lockout + cooldown  
- Device tracking  

**Phase 3 — Suspicious Login Detection**  
- More advanced heuristics (geo-based “impossible travel”)  
- IP reputation and ASN considerations  
- Risk scoring system  
- Step-up authentication when risk is high  
- User-visible login history  

**Phase 4 — Admin Security Console**  
- Rich admin dashboard for users & login attempts  
- Filters and search (by email, IP, time window, risk level)  
- Flag high-risk accounts  
- Lock/unlock accounts  
- Force password reset  
- Export audit logs (CSV / JSON)  


## Security Overview

The Secure Login System is designed to model real-world identity and access security rather than a simple “login form.”

**Authentication and Session Security**  
- Passwords are hashed with bcrypt before storage in MongoDB.  
- Authentication is implemented with JWTs set in HttpOnly cookies, reducing exposure to XSS-based token theft.  
- Cookie options adapt to environment:
  - Development: `sameSite=lax`, non-secure cookies for localhost  
  - Production: `sameSite=none`, `secure=true` for cross-site HTTPS between frontend and API  

**Monitoring and Audit Logging**  
- Every login attempt is recorded with:
  - Email  
  - IP address  
  - User agent  
  - Success/failure flag  
  - Timestamps  
- This provides an audit trail for incident response and supports future threat detection logic.  

**Suspicious Login Detection (Current v1.1)**  
- Simple heuristics mark certain login attempts as suspicious:
  - Multiple failed attempts in a short time window  
  - Successful login from a new IP for the same account  
- Suspicious attempts are tagged with a boolean (`suspicious`) and structured reasons (e.g., `"multiple_failed_attempts_recently"`, `"new_ip_for_account"`), making them easy to query and visualize.  

**Administrative Visibility**  
- Admin-only endpoints and UI provide visibility into recent login activity.  
- The admin page surfaces:
  - Success/fail status  
  - Suspicious flag  
  - IP and user agent context  
  - Human-readable timestamps  
- Admin access is enforced via role-based checks on top of JWT authentication.  

Future work expands on this base with email verification, MFA, rate limiting, account lockout, and more advanced risk scoring.


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