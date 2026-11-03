FROM golang:1.22-alpine AS builder
WORKDIR /src

# Download modules based on the committed lockfile before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./src/cmd/server

# Distroless non-root runtime: no shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/gateway /app/gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/gateway"]
