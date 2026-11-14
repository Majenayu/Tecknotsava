# Security policy

Do not report vulnerabilities in public issues. Share a minimal reproduction privately with the repository owner and do not include live credentials or personal data.

Use environment variables for secrets, rotate any accidentally exposed credential immediately, and restrict database, storage, OAuth, and webhook access to the least privilege required. Before production deployment, enable HTTPS, validate input, apply authentication and authorization, and configure rate limits and logging appropriate to the application.

This repository is maintained on a best-effort basis; deployments should be independently reviewed before processing real user data.
