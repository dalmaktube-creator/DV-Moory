# Security policy

Report security issues privately to the repository owner. Do not open a public issue containing secrets or exploit details.

## Never commit

- GitHub App private keys
- Bearer tokens
- SSH deploy keys
- Android keystores
- Passwords, API keys, `.env` files, or credential exports

## Supported deployment

Only the latest release is supported. Rotate the Notion bearer token and GitHub App key after suspected exposure. GitHub App installation must remain limited to explicitly selected repositories.
