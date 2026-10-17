# HTTP Security Header & Cookie Hardening Auditor

A lightweight, automated defensive security auditing utility built in Python to evaluate the defensive posture of modern web endpoints against OWASP standards.

---

## Technical Overview

Modern browsers rely on critical response headers to mitigate client-side vulnerabilities, such as Cross-Site Scripting (XSS), Clickjacking, MIME sniffing, and SSL Stripping. 

This tool automates compliance auditing by inspecting HTTP response headers and session cookie parameters without executing intrusive payloads.

---

## Evaluated Controls

* **Strict-Transport-Security (HSTS):** Enforces encrypted HTTPS communication channels.
* **Content-Security-Policy (CSP):** Restricts unauthorized script and resource execution.
* **X-Frame-Options:** Prevents UI redress / iframe embedding attacks.
* **X-Content-Type-Options:** Enforces strict MIME typing (`nosniff`).
* **Referrer-Policy:** Limits referrer information leakage.
* **Permissions-Policy:** Restricts browser hardware access vectors.
* **Cookie Flags:** Audits `Secure`, `HttpOnly`, and `SameSite` configurations.

---

## Installation & Setup

1. Clone repository:
   ```bash
   git clone [https://github.com/Raihan-143/web-security-auditor.git]
   cd web-security-auditor

## Author 
Md Raihan Hasan Rana - Cybersecurity Enthusiast   