# Derleme Aşaması
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY src/ ./src/

RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o gateway ./src/cmd/server/main.go

# Minimal Çalışma Zamanı
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/gateway .

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/app/gateway"]
