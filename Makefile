BIN := bin
API_BIN := $(BIN)/api
WORKER_BIN := $(BIN)/worker

# Build both binaries
.PHONY: build
build:
	@mkdir -p $(BIN)
	go build -o $(API_BIN) ./cmd/api
	go build -o $(WORKER_BIN) ./cmd/worker

# Run all tests with race detector and coverage
.PHONY: test
test:
	go test ./... -race -cover -count=1

# Run linter (requires golangci-lint: https://golangci-lint.run/usage/install/)
.PHONY: lint
lint:
	golangci-lint run ./...

# Regenerate sqlc type-safe queries (requires sqlc: https://docs.sqlc.dev/en/latest/overview/install.html)
.PHONY: sqlc
sqlc:
	sqlc generate

# Database migration helpers (requires migrate CLI: https://github.com/golang-migrate/migrate/tree/master/cmd/migrate)
# DB_DSN must be set, e.g.: export DB_DSN="asm:changeme@tcp(localhost:3306)/asm?parseTime=true&loc=UTC"
.PHONY: migrate-up
migrate-up:
	migrate -path=./migrations -database="mysql://$(DB_DSN)" up

.PHONY: migrate-down
migrate-down:
	migrate -path=./migrations -database="mysql://$(DB_DSN)" down 1

.PHONY: migrate-status
migrate-status:
	migrate -path=./migrations -database="mysql://$(DB_DSN)" version

# Bring up the full local stack
.PHONY: docker-up
docker-up:
	docker compose up

.PHONY: docker-build
docker-build:
	docker compose build

# Generate a new migration file (usage: make migrate-create NAME=create_asset_table)
.PHONY: migrate-create
migrate-create:
	migrate create -ext sql -dir ./migrations -seq $(NAME)

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(BIN)
