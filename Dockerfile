FROM golang:1.25.14-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -o auth-service .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-service .
COPY --from=builder /app/keys ./keys

EXPOSE 4000
CMD ["./auth-service"]
