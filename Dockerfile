# Derleme Aşaması
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY src/ ./src/
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o gateway ./src/cmd/server/main.go

# CRITICAL FIX: Minimal Distroless Çalışma Zamanı (Zero-Shell, Zero-OS vulnerabilities)
FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /app
COPY --from=builder /app/gateway .

# distroless:nonroot uses uid:gid 65532:65532
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/gateway"]
