SHELL := /bin/bash
COMPOSE := docker compose -f docker-compose.dev.yml
TEST_DSN ?= postgres://vertex:vertex@localhost:5433/vertex_auth?sslmode=disable

.DEFAULT_GOAL := help
.PHONY: help build run test test-integration vet lint tidy db-up db-down db-reset migrate-info

help:
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## build binary
	CGO_ENABLED=0 go build -o bin/auth-service .

run: ## รัน service
	go run .

vet: ## go vet
	go vet ./... && go vet -tags=integration ./...

test: ## unit test
	go test -race -count=1 ./...

test-integration: ## integration test (ต้อง make db-up ก่อน)
	TEST_DATABASE_URL="$(TEST_DSN)" go test -race -count=1 -tags=integration ./...

tidy: ## go mod tidy
	go mod tidy && git diff --exit-code go.mod go.sum

db-up: ## ยก postgres + รัน migration (ต้อง clone vertex-migrations ไว้ข้างกัน)
	@test -d ../vertex-migrations || { echo "ไม่พบ ../vertex-migrations"; exit 1; }
	$(COMPOSE) up -d postgres && $(COMPOSE) run --rm flyway

db-down: ## ปิด + ลบ volume
	$(COMPOSE) down -v

db-reset: db-down db-up ## ล้างแล้วสร้างใหม่

migrate-info: ## flyway info
	$(COMPOSE) run --rm flyway info
