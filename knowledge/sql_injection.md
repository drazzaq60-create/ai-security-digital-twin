# SQL Injection

SQL injection is a vulnerability where an attacker inserts malicious SQL code into an application's input fields (like a login form or search box). If the application builds its database queries by directly gluing user input into the query string, the attacker's input changes the meaning of the query. This can let them bypass logins, read other users' data, or dump entire database tables.

A classic example is typing ' OR '1'='1 into a login field, which can make the query always evaluate to true and grant access without a valid password.

How to fix: use parameterized queries (prepared statements) so user input is always treated as data, never as executable SQL. Validate and sanitize all inputs, run the application with a least-privilege database account, and prefer an ORM that parameterizes queries by default.
