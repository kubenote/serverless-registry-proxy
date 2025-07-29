FROM golang:1.20.1-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src/app
COPY . .
RUN go build -o /app

FROM alpine
RUN apk add --no-cache ca-certificates

# Copy built binary
COPY --from=build /app /app

# Set working directory for future volume mounts (optional)
WORKDIR /app

# Uncomment to support GCP registry auth
# COPY key.json /key.json
# ENV GOOGLE_APPLICATION_CREDENTIALS=/key.json

# Optional labels for image clarity
LABEL org.opencontainers.image.source="https://github.com/kubenote/KubeForge"
LABEL org.opencontainers.image.title="GHCR Proxy"
LABEL org.opencontainers.image.description="A Docker Registry V2 reverse proxy with TLS support"

# You can expose port 443 here if using TLS directly in the container
EXPOSE 443

ENTRYPOINT ["/app"]