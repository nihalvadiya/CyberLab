#  Flask Web Security Lab

A hands-on **web application security playground** built with Flask to demonstrate common OWASP Top 10 vulnerabilities — along with their real-world mitigations.

This project is designed for **educational, defensive, and portfolio purposes**, showing both how attacks work and how to properly secure modern web applications.

---

##  Project Overview

This lab simulates a realistic authentication-based web application and demonstrates multiple critical security flaws in a controlled environment.

Each vulnerability includes:

*  An intentionally vulnerable implementation
*  A properly secured version
*  Clear learning objectives

The project emphasizes **defense in depth** and real AppSec thinking.

---

##  Tech Stack

* **Backend:** Flask (Python)
* **Database:** SQLite
* **Password Hashing:** bcrypt
* **Session Management:** Flask sessions
* **Frontend:** Jinja2 templates + minimal CSS
* **Security Controls:** CSP, CSRF tokens, cookie hardening

---

##  Features

###  Authentication System

* User registration with bcrypt hashing
* Secure login with parameterized queries
* Login attempt lockout protection
* Session-based authentication
* Hardened session cookies

---

###  Security Labs Implemented

This project intentionally includes vulnerable endpoints for learning purposes.

---

##  SQL Injection (SQLi)

**Vulnerable endpoint**

```
/login_vuln
```

**Secure endpoint**

```
/login
```

**What it demonstrates**

* String-formatted SQL risks
* Authentication bypass
* Parameterized query protection

---

##  Stored Cross-Site Scripting (Stored XSS)

**Vulnerable endpoint**

```
/profile
```

**Secure endpoint**

```
/profile_safe
```

**What it demonstrates**

* Persistent script injection
* Browser execution risks
* Jinja auto-escaping protection

---

##  Reflected Cross-Site Scripting (Reflected XSS)

**Vulnerable endpoint**

```
/search
```

**Secure endpoint**

```
/search_safe
```

**What it demonstrates**

* URL-based injection
* Immediate script execution
* Output encoding importance

---

##  Session Hijacking Simulation

**Lab endpoint**

```
/steal
```

**What it demonstrates**

* Cookie exfiltration via XSS
* Importance of HttpOnly cookies
* Session security fundamentals

---

##  Cross-Site Request Forgery (CSRF)

**Endpoint**

```
/transfer
```

**What it demonstrates**

* Forged authenticated requests
* Browser auto-cookie behavior
* CSRF token validation
* SameSite cookie impact

---

##  Broken Access Control

**Vulnerable endpoint**

```
/admin_vuln
```

**Secure endpoint**

```
/admin_safe
```

**What it demonstrates**

* Authentication vs authorization
* Missing role checks
* Proper access enforcement

---

##  Security Controls Implemented

This lab demonstrates layered defensive techniques:

* ✅ bcrypt password hashing
* ✅ Parameterized SQL queries
* ✅ Login brute-force lockout
* ✅ HttpOnly session cookies
* ✅ SameSite cookie configuration
* ✅ CSRF token validation
* ✅ Content Security Policy (CSP)
* ✅ Role-based authorization checks
* ✅ Jinja template auto-escaping

Together these illustrate **defense in depth**.

---

##  Content Security Policy

The application implements a strict CSP:

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
```

**Security impact**

* Blocks inline script execution
* Mitigates many XSS payloads
* Adds browser-side protection layer

---

##  Threat Model (Simplified)

This lab assumes:

* Attackers can supply malicious input
* Victims may be authenticated
* Browsers enforce modern cookie rules
* Developers may introduce common mistakes

The goal is to demonstrate how **layered defenses reduce real risk**.

---

##  Recommended Testing Flow

For reviewers or learners:

1. Register a normal user
2. Test secure login
3. Attempt SQL injection on `/login_vuln`
4. Try stored XSS on `/profile`
5. Try reflected XSS on `/search`
6. Observe CSP blocking behavior
7. Attempt CSRF using the attacker page
8. Test broken access control endpoints
9. Compare vulnerable vs secure implementations

---

##  Project Structure

```
flask-web-security-lab/
│
├── app.py
├── requirements.txt
├── README.md
│
├── database/
│   └── auth.db
│
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   └── register.html
│
├── static/
│   └── style.css
│
└── docs/
```

---

##  How to Run Locally

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd flask-web-security-lab
```

---

### 2. Install dependencies

```bash
py -m pip install -r requirements.txt
```

---

### 3. Run the application

```bash
py app.py
```

---

### 4. Open in browser

```
http://127.0.0.1:5000
```

---

##  Security Disclaimer

This project intentionally contains vulnerable code for **educational purposes only**.

* Do NOT deploy publicly
* Do NOT use in production
* Use only in controlled environments

---

##  Future Enhancements

Planned improvements:

* Role storage in database
* CSP with nonces
* Password reset flow
* Rate limiting by IP
* Dockerized deployment
* Expanded security headers
* IDOR demonstration

---

##  Author

Built as part of a hands-on cybersecurity learning journey focused on:

* OWASP Top 10
* Secure coding practices
* Real-world web exploitation
* Defense-in-depth engineering

---

⭐ If you found this project useful, consider starring the repository.
