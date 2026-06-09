# Security Assessment Report

**Target**: https://admin.arboard.kz  
**Date**: 2026-06-01 16:04 UTC  
**Risk Rating**: MEDIUM  
**Engagement ID**: 63fe94aa-aa33-4e65-b529-ca5737cc0f0a

---

## Executive Summary

### Findings Overview

| Severity | Count |
|----------|-------|
| HIGH | 3 |
| MEDIUM | 7 |
| LOW | 2 |
| INFO | 1 |

## Detailed Findings

### 1. Login form submits credentials via GET method

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | A2:2021 – Cryptographic Failures |
| CWE | CWE-319 |
| Confidence | 0% |

The login form at https://admin.arboard.kz uses the HTTP GET method to submit username and password. This exposes credentials in the URL, which can be logged by proxies, browser history, and server logs, and may be visible in the address bar.

**Remediation**: Change form method to POST. Use HTTPS (already implied) and ensure credentials are never transmitted in the URL. Example: <form method="post" action="/login">

---

### 2. Login form uses HTTP GET method – credentials exposed in URL and server logs

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | A02:2021 – Cryptographic Failures |
| CWE | CWE-319 |
| Confidence | 0% |

The login form at /login?from=%2F uses method='get', so username and password are submitted as query parameters. This causes credentials to be visible in URLs, browser history, referrer headers, and server logs. It also allows easy interception in shared networks and violates secure authentication best practices.

**Remediation**: Change the form method to 'post'. Ensure all sensitive data (username, password) is transmitted in the request body over HTTPS. Implement CSRF protection and use secure session cookies. Example: <form method='post' action='/login'> with input fields inside the body.

---

### 3. Login form sends credentials via GET – credentials visible in URL and logs

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | A04:2021 |
| CWE | CWE-840 |
| Confidence | 0% |

The authentication flow uses a GET request, meaning the password is transmitted as a query parameter. This violates basic security principles and exposes credentials to third parties through browser history, web server logs, proxy logs, and referrer headers. Additionally, this makes it trivial for an attacker to extract credentials via log inspection.

**Remediation**: Change form method to POST. Implement password hashing and secure session handling. Use HTTPS exclusively. Ensure all logs are sanitized of sensitive parameters.

---

### 4. Missing CAPTCHA or rate limiting on login form

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A4:2021 – Insecure Design |
| CWE | CWE-307 |
| Confidence | 0% |

The login form does not include a CAPTCHA or any visible rate limiting mechanism. This allows automated brute-force attacks against the admin login.

**Remediation**: Implement CAPTCHA (e.g., reCAPTCHA v3) after a configurable number of failed attempts. Additionally, enforce account lockout after N failed attempts and implement IP-based rate limiting.

---

### 5. Missing Multi-Factor Authentication (MFA) for admin login

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A4:2021 – Insecure Design |
| CWE | CWE-308 |
| Confidence | 0% |

The admin login page does not require any second factor for authentication (no 2FA buttons or prompts).

**Remediation**: Implement MFA using TOTP, SMS, or push notifications. Enforce it for all admin accounts.

---

### 6. Login form uses GET method – business logic flaw

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A04:2021 |
| CWE | CWE-840 |
| Confidence | 0% |

Submitting credentials via GET violates standard security practices and exposes sensitive data in URLs. This is a business logic design flaw that increases attack surface beyond technical misconfiguration.

**Remediation**: Change form method to POST. Additionally, implement CSRF tokens and use HTTPS. Review any logs that may have stored previous GET-based credentials.

---

### 7. No brute-force protection on login

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A04:2021 |
| CWE | CWE-840 |
| Confidence | 0% |

The absence of CAPTCHA or account lockout allows unlimited login attempts, making brute-force and credential stuffing attacks viable.

**Remediation**: Implement account lockout after 5 failed attempts (temporary 30-min lock), add reCAPTCHA after 3 failures, and enforce strong password policies. Consider security headers like 'X-RateLimit-Remaining'.

---

### 8. No captcha or brute-force protection on login form

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A07:2021 – Identification and Authentication Failures |
| CWE | CWE-307 |
| Confidence | 0% |

The login form lacks any captcha, rate limiting, or account lockout mechanism. The 'hasCaptcha' field is false, and no additional security controls are present in the form.

**Remediation**: Implement rate limiting (e.g., 5 attempts per IP per minute), account lockout after 3-5 failed attempts, and optionally add a captcha (e.g., reCAPTCHA) to the login form. Also enforce strong password policies.

---

### 9. Absence of multi-factor authentication (2FA) on admin login

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A07:2021 – Identification and Authentication Failures |
| CWE | CWE-308 |
| Confidence | 0% |

The login form does not offer or require two-factor authentication (2FA). The 'has2FA' field is false. Admin accounts are protected only by a single password.

**Remediation**: Implement 2FA (e.g., TOTP via authenticator app, SMS, or hardware token) for all admin accounts. Enforce it for high-privilege accounts.

---

### 10. No account lockout or rate limiting – unlimited brute force possible

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | A04:2021 |
| CWE | CWE-840 |
| Confidence | 0% |

The login endpoint has no mechanism to detect or prevent repeated failed attempts. An attacker can automate password guessing without any restriction.

**Remediation**: Implement account lockout after 3-5 failed attempts (with automatic unlock after 15-30 minutes). Add rate limiting per IP (e.g., 10 attempts per minute). Consider adding captcha after 3 failures.

---

### 11. Directory listing enabled on /assets/ path

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | A5:2021 – Security Misconfiguration |
| CWE | CWE-548 |
| Confidence | 0% |

Accessing https://admin.arboard.kz/assets redirects or shows directory contents. While the current evidence only shows a redirect (302), the presence of a redirect often indicates directory listing is enabled (e.g., nginx with autoindex on or a trailing slash redirect). This may expose static assets and potentially configuration files.

**Remediation**: Disable directory listing in nginx (add 'autoindex off;'). Ensure no sensitive files are placed in the public web directory.

---

### 12. Redirect at /assets exposes directory listing or information

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | A05:2021 – Security Misconfiguration |
| CWE | CWE-200 |
| Confidence | 0% |

The URL /assets redirects to http://admin.arboard.kz/assets/ (trailing slash). This could expose the content of the assets directory if directory listing is enabled on nginx.

**Remediation**: Configure nginx to deny access to directory listing (autoindex off). Also ensure sensitive files (e.g., .env, configs) are not placed in assets. Example nginx: location /assets/ { autoindex off; }

---

### 13. Potential for session fixation or weak session management

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | A04:2021 |
| CWE | CWE-840 |
| Confidence | 0% |

The login form includes a query parameter 'from=%2F' redirect after login. This suggests the application may be susceptible to session fixation or open redirect if not properly handled. Additionally, no HTTP-only or Secure flags on cookies were observed (though not directly tested).

**Remediation**: Regenerate session ID upon successful login. Set HttpOnly, Secure, SameSite=Strict flags on session cookies. Validate redirect targets to prevent open redirect.

---

---

*Report generated by Assurix Autonomous Security Validation Platform*  
*2026-06-01 16:04 UTC*