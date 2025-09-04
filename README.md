# SSO Service - Citadelas

Single Sign-On (SSO) service for Citadelas microservices architecture. Provides centralized authentication and authorization using JWT tokens with refresh token mechanism.

## 🏗️ Overview

This service handles:
- User registration and authentication
- JWT access and refresh token management
- Admin role verification
- Secure password hashing with bcrypt
- PostgreSQL database integration
- gRPC API for inter-service communication

## 🚀 Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Docker & Docker Compose
- Protocol Buffers compiler

### Installation and Setup

1. **Clone the repository**
```bash
git clone https://github.com/Citadelas/sso.git
cd sso
```

2. **Create configuration file**
Create `config/local.yaml`:
```yaml
env: "local"
storage_path: "postgres://postgres:postgres@localhost:5432/sso?sslmode=disable"
token_ttl: "1h"
token_ref: "24h"

grpc:
  port: 44043
  timeout: "5s"
```

3. **Run database migrations**
```bash
# Using golang-migrate
migrate -path ./migrations -database "postgres://postgres:postgres@localhost:5432/sso?sslmode=disable" up
```

4. **Start the service**
```bash
# Local development
go run cmd/sso/main.go -config=config/local.yaml

# Or with Docker Compose
docker-compose up --build
```

The service will be available on `localhost:44043` (gRPC)

## 📡 gRPC API

### Authentication Service

```protobuf
service Auth {
    rpc Login(LoginRequest) returns (LoginResponse);
    rpc Register(RegisterRequest) returns (RegisterResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
    rpc IsAdmin(IsAdminRequest) returns (IsAdminResponse);
}
```

### Message Types

**LoginRequest**
```protobuf
message LoginRequest {
    string email = 1;
    string password = 2;
    int32 app_id = 3;
}
```

**LoginResponse**
```protobuf
message LoginResponse {
    string token = 1;         // JWT access token
    string refresh_token = 2; // JWT refresh token
}
```

**RegisterRequest**
```protobuf
message RegisterRequest {
    string email = 1;
    string password = 2;
}
```

**RefreshTokenRequest**
```protobuf
message RefreshTokenRequest {
    string refresh_token = 1;
    int32 app_id = 2;
}
```

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    pass_hash BYTEA NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_email ON users (email);
```

### Apps Table
```sql
CREATE TABLE apps (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_PATH` | Path to configuration file | `./config/local.yaml` |
| `POSTGRES_URL` | PostgreSQL connection string | - |
| `JWT_SECRET` | JWT signing secret | - |
| `GRPC_PORT` | gRPC server port | `44043` |

### Configuration Structure

```yaml
env: "local|dev|prod"
storage_path: "postgres://user:pass@host:port/dbname?sslmode=disable"
token_ttl: "1h"      # Access token lifetime
token_ref: "24h"     # Refresh token lifetime

grpc:
  port: 44043
  timeout: "5s"

logging:
  level: "info"
  format: "json"
```

## 🏃‍♂️ Development

### Project Structure

```
sso/
├── cmd/
│   ├── sso/
│   │   └── main.go           # Service entry point
│   └── migrator/
│       └── main.go           # Database migrator
├── internal/
│   ├── app/                  # Application setup
│   ├── config/               # Configuration management
│   ├── domain/
│   │   └── models/          # Domain models
│   ├── grpc/
│   │   └── auth/            # gRPC server implementation
│   ├── services/
│   │   └── auth/            # Business logic
│   ├── storage/             # Database layer
│   │   ├── postgresql/      # PostgreSQL implementation
│   │   └── sqlite/          # SQLite implementation (dev)
│   └── lib/
│       ├── jwt/             # JWT utilities
│       └── logger/          # Logging utilities
├── migrations/              # Database migrations
├── docker-compose.yml
├── Dockerfile
└── README.md
```

### Adding New Features

1. Define new message types in [protos repository](https://github.com/Citadelas/protos)
2. Implement business logic in `internal/services/auth`
3. Add gRPC handlers in `internal/grpc/auth`
4. Create database migrations if needed
5. Update configuration and documentation

## 🧪 Testing

### Unit Tests
```bash
go test ./internal/...
```

### Integration Tests
```bash
# Start test database
docker run --name test-postgres -e POSTGRES_PASSWORD=test -d -p 5433:5432 postgres:15

# Run integration tests
TEST_POSTGRES_URL="postgres://postgres:test@localhost:5433/test?sslmode=disable" go test -tags=integration ./...
```

### gRPC Testing with grpcurl
```bash
# Login
grpcurl -plaintext -d '{"email":"user@example.com","password":"password","app_id":1}' \
  localhost:44043 sso.Auth/Login

# Register
grpcurl -plaintext -d '{"email":"newuser@example.com","password":"password"}' \
  localhost:44043 sso.Auth/Register

# Refresh token
grpcurl -plaintext -d '{"refresh_token":"your_refresh_token","app_id":1}' \
  localhost:44043 sso.Auth/RefreshToken
```

## 🐳 Docker Deployment

### Docker Compose
```yaml
version: '3.8'
services:
  postgres-db:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: sso
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  db-migrate:
    image: migrate/migrate
    command: -path=/migrations -database postgres://postgres:postgres@postgres-db:5432/sso?sslmode=disable up
    volumes:
      - ./migrations:/migrations
    depends_on:
      - postgres-db

  sso-app:
    build: .
    ports:
      - "44043:44043"
    environment:
      - CONFIG_PATH=/app/config/local.yaml
    depends_on:
      - db-migrate
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:44043"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  pgdata:
```

### Production Configuration
```yaml
env: "prod"
storage_path: "${POSTGRES_URL}"
token_ttl: "15m"
token_ref: "7d"

grpc:
  port: 44043
  timeout: "5s"
  tls:
    cert_file: "/certs/server.crt"
    key_file: "/certs/server.key"

logging:
  level: "info"
  format: "json"
```

## 🛡️ Security Considerations

### Password Security
- Uses bcrypt with default cost (10)
- Passwords are hashed before storage
- No plain text passwords in logs

### JWT Security
- Access tokens are short-lived (1 hour default)
- Refresh tokens are longer-lived (24 hours default)
- Tokens are signed with HMAC SHA256
- Different secrets for different applications

### Database Security
- Prepared statements prevent SQL injection
- Connection string should use SSL in production
- Regular security updates for PostgreSQL

### Recommended Security Enhancements
- [ ] Rate limiting for authentication endpoints
- [ ] Account lockout after failed attempts
- [ ] Refresh token rotation
- [ ] OAuth 2.0 / OpenID Connect support
- [ ] Multi-factor authentication
- [ ] Audit logging for authentication events

## 📊 Monitoring

### Health Checks
Implement health check endpoint for load balancers:
```go
func (s *Server) Health() (*healthpb.HealthCheckResponse, error) {
    return &healthpb.HealthCheckResponse{
        Status: healthpb.HealthCheckResponse_SERVING,
    }, nil
}
```

### Metrics (Planned)
- Authentication success/failure rates
- Token refresh rates
- Database connection pool metrics
- gRPC request duration and count

### Logging
Structured JSON logs include:
- Request ID for tracing
- User ID (when available)
- Operation type
- Error details
- Performance metrics

## 🚧 Roadmap

### v1.1
- [ ] Rate limiting middleware
- [ ] Account lockout mechanism
- [ ] Refresh token rotation
- [ ] Prometheus metrics

### v1.2
- [ ] OAuth 2.0 provider support
- [ ] Multi-factor authentication
- [ ] Role-based access control (RBAC)
- [ ] Session management

### v2.0
- [ ] OpenID Connect provider
- [ ] SAML support
- [ ] Audit logging
- [ ] Admin dashboard

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines
- Follow Go best practices and conventions
- Write tests for new features
- Update documentation
- Use structured logging
- Follow semantic versioning

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🔗 Related Services

- [API Gateway](https://github.com/Citadelas/api-gateway) - HTTP/REST API gateway
- [Task Service](https://github.com/Citadelas/task) - Task management service
- [Protos](https://github.com/Citadelas/protos) - Protocol Buffers contracts

## 📞 Support

For questions and support:
- Create an [issue](https://github.com/Citadelas/sso/issues)
- Check [documentation](https://github.com/Citadelas/sso/wiki)
- Contact maintainer: [@muerewa](https://github.com/muerewa)

---

**Maintainer**: [muerewa](https://github.com/muerewa)  
**Organization**: [Citadelas](https://github.com/Citadelas)
