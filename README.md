# Auth Service

Authentication microservice: OAuth2, JWT, refresh tokens, rate limiting, and multi-factor auth.

## Features
- **OAuth2**: Google, GitHub, and custom OAuth2 providers
- **JWT Auth**: Access and refresh token rotation
- **MFA**: Time-based one-time passwords (TOTP)
- **Rate Limiting**: Per-user and per-IP throttling
- **Session Management**: Redis-backed session store
- **Audit Log**: Complete authentication event logging

## Tech Stack
- **Language**: Go 1.21
- **Framework**: Gin
- **Database**: PostgreSQL
- **Cache**: Redis
- **Auth**: OAuth2, JWT, bcrypt

## Quick Start
```bash
git clone https://github.com/FlourishP/auth-service
cd auth-service
go build -o auth-service .
./auth-service
```

## License
MIT — see [LICENSE](LICENSE)
