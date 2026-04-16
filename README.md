# 🛡️ InnoGen Pharma Universal SSO Provider
**Centralized Identity & Access Management (IAM) built with FastAPI & Postgres**

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![OAuth2](https://img.shields.io/badge/OAuth2-EB5424?style=for-the-badge&logo=auth0&logoColor=white)](https://oauth.net/2/)

## 🛠 Tech Stack

| Category | Tools |
| :--- | :--- |
| **Framework** | **FastAPI** (Asynchronous Python 3.12) |
| **Database** | **PostgreSQL** (via SQLAlchemy Async/AioSQLP) |
| **DevOps** | **Docker & Docker Compose** (Containerized Microservices) |
| **Auth Protocols** | **OAuth 2.0 / OpenID Connect** (Google & Apple) |
| **Identity Logic** | **cPanel UAPI** Integration (Legacy Mailbox Verification) |
| **Security** | HTTP-only Cookies, JWT Signing, User-Agent/IP Binding |

---

## 🎯 Project Overview
The **Universal SSO Provider** is the backbone of the InnoGen Pharma ecosystem. It provides a centralized "Login once, access everywhere" experience across multiple domains (`.com`, `.ph`, and local environments).

### 🌟 High-Level Architecture
1. **Email-First Routing:** Intelligently routes users based on their domain:
   - `@innogen-pharma.com` ➔ Managed via **Google OAuth**.
   - `@innogen-pharma.ph` ➔ Managed via **cPanel Mailbox API** + Local App Passwords.
2. **Session Persistence:** Issues a cryptographically hashed `device_token` (HTTP-only) bound to the user's IP and User-Agent to prevent session hijacking.
3. **Cross-Origin Capability:** Securely configured CORS for internal pharmaceutical domains and local development environments.

---

## 🚀 Key Professional Capabilities

### 🔐 Multi-Provider Authentication
* **Hybrid Auth Flow:** Seamlessly integrates modern OAuth (Google/Apple) with legacy system verification (cPanel UAPI).
* **Credential Security:** Implemented secure local app password hashing and storage within Postgres for non-Google users.

### 🏗 Microservices & Containerization
* **Scalable Deployment:** Fully containerized using Docker, allowing for "one-command" deployment and consistent staging/production environments.
* **Health Monitoring:** Built-in health check endpoints for automated load balancer and uptime monitoring.

### 🌐 Developer Experience (DX) for Internal Teams
* **Session Verification API:** Exposed a `GET /api/v1/verify-session` endpoint, making it trivial for other internal apps to check authentication state.
* **SDK-like Integration:** Provided clear documentation and code snippets for internal developers to implement "Continue with InnoGen" buttons.

---

## ⚙️ Development & Quick Start

### Prerequisites
- Docker & Docker Compose
- Registered Google/Apple Developer Client IDs

### One-Command Start
```bash
docker compose up -d --build
```

The API will be available at `http://127.0.0.1:8520`.

---

## 🔒 Security Infrastructure
- **Zero-Trust Config:** Secrets are managed strictly via `.env` files.
- **Cookie Protection:** Uses `SameSite=None` and `Secure` flags for cross-domain cookie transmission.
- **State Verification:** Implements OAuth `state` parameters to prevent Cross-Site Request Forgery (CSRF).

---

## 📜 License & Intellectual Property
**Copyright (c) 2026 Benedic Cater / InnoGen Pharmaceuticals Inc. (Solvang)**

**All Rights Reserved.**
This repository is published for **portfolio review and technical demonstration purposes only.**

**Strict Restrictions:**
- **No Reproduction:** No part of this code may be copied, modified, or distributed.
- **Brand Protection:** Use of the "InnoGen" or "Solvang" name, branding, or logos is strictly prohibited.
- **Data Privacy:** Use of any proprietary data or business logic contained herein for commercial or personal projects is strictly prohibited.

_For professional inquiries or permission requests, please contact Benedic Cater._
