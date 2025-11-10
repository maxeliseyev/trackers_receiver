.PHONY: help build test test-integration run docker-build docker-up docker-down docker-logs clean

# Variables
BINARY_NAME=receiver
DOCKER_IMAGE=trackers-receiver
VERSION?=dev

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building $(BINARY_NAME)..."
	go build -o bin/$(BINARY_NAME) ./cmd/receiver

test: ## Run unit tests
	@echo "Running unit tests..."
	go test -v -short ./...

test-integration: ## Run integration tests (requires Redis)
	@echo "Running integration tests..."
	go test -v ./test/integration/...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

run: build ## Build and run the application
	@echo "Running $(BINARY_NAME)..."
	./bin/$(BINARY_NAME)

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) -t $(DOCKER_IMAGE):latest .

docker-up: ## Start services with docker-compose
	@echo "Starting services..."
	docker-compose up -d
	@echo "Services started. Logs: make docker-logs"

docker-down: ## Stop services
	@echo "Stopping services..."
	docker-compose down

docker-restart: docker-down docker-up ## Restart all services

docker-logs: ## Show logs
	docker-compose logs -f

docker-logs-receiver: ## Show receiver logs only
	docker-compose logs -f receiver

docker-logs-redis: ## Show redis logs only
	docker-compose logs -f redis

docker-ps: ## Show running containers
	docker-compose ps

docker-clean: docker-down ## Clean up Docker resources
	@echo "Cleaning up Docker resources..."
	docker-compose down -v
	docker rmi $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION) 2>/dev/null || true

lint: ## Run linter
	@echo "Running linter..."
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed"

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.log

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Development helpers
dev: ## Run in development mode (with auto-reload if installed)
	@command -v air >/dev/null 2>&1 && air || make run

redis-cli: ## Connect to Redis CLI
	docker-compose exec redis redis-cli

redis-monitor: ## Monitor Redis commands
	docker-compose exec redis redis-cli monitor

redis-clear: ## Clear Redis database (use with caution!)
	@echo "Clearing Redis database..."
	docker-compose exec redis redis-cli FLUSHDB

# Production helpers
prod-build: ## Build optimized production binary
	@echo "Building production binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		-o bin/$(BINARY_NAME) \
		./cmd/receiver

prod-docker: ## Build production Docker image
	@echo "Building production Docker image..."
	docker build --build-arg VERSION=$(VERSION) -t $(DOCKER_IMAGE):$(VERSION) .

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...
