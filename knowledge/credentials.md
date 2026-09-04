# Credential Weaknesses

Hardcoded credentials occur when usernames, passwords, API keys, or service-account secrets are written directly into source code or configuration files. Anyone who reads the code (or a leaked repository) gains instant access. Service accounts are especially dangerous because they often carry broad permissions.

Weak password policies allow easily guessed or brute-forced passwords, letting attackers log into admin panels and user accounts.

How to fix: never store secrets in code; keep them in environment variables or a dedicated secrets manager. Rotate credentials regularly. Enforce strong password rules (length, complexity, and multi-factor authentication) and lock accounts after repeated failed login attempts.
