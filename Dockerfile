# Start from the official Golang image
FROM golang:1.24 AS builder

# Set working directory inside the container
WORKDIR /app

# Copy go mod and go sum files first (for caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o sso ./cmd/sso

# Use minimal base image
FROM alpine:latest

# Set working directory for runtime
WORKDIR /app

# Copy built binary from builder stage
COPY --from=builder /app/sso .

COPY --from=builder /app/config ./config

# Expose port if needed (example: 8080)
EXPOSE 44043

ENV CONFIG_PATH=/app/config/local.yaml

# Run the executable
CMD ["./sso"]
