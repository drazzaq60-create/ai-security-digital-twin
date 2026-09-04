# Broken Access Control

Excessive permissions happen when an account (such as a service account or an application user) is granted far more access than it needs. If that account is ever compromised, the attacker inherits all of its permissions. A database account with full administrative rights turns a small breach into a complete data compromise.

Giving the web tier or an admin panel direct database access is dangerous, because a single web-server compromise can then reach the database with no additional barrier in the way.

How to fix: apply the principle of least privilege - give every account only the minimum permissions it needs to do its job. Separate the tiers so the web layer cannot talk directly to the database with elevated rights. Review and audit permissions regularly and remove access that is no longer needed.
