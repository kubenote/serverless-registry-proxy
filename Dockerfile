# Build stage
FROM golang:1.20.1-alpine AS builder

# Install needed tools
RUN apk add --no-cache git ca-certificates

WORKDIR /src/app

# Reduce cache invalidation by copying go.mod first
COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o /app

# Final minimal stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

# Add a non-root user for security
RUN addgroup -S app && adduser -S app -G app
USER app

COPY --from=builder /app /app

# Expose as HTTP by default (let DO handle TLS)
EXPOSE 8080

HEALTHCHECK CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

ENTRYPOINT ["/app"]
