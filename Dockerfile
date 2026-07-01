# ── builder: compile both binaries ───────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Fetch dependencies before copying source (cache layer)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/api  ./cmd/api  && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/worker ./cmd/worker

# ── final: minimal runtime image ─────────────────────────────────────────────
FROM alpine:3.19 AS final

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/bin/api    ./api
COPY --from=builder /app/bin/worker ./worker

# Default to the API binary; docker-compose overrides command per service
ENTRYPOINT []
CMD ["/app/api"]
