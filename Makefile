.PHONY: dev dev-build down migrate test test-cov lint format worker consumer k8s-deploy help

PYTHON := python3
PIP := pip3
DOCKER_COMPOSE := docker compose

# ─── Development ─────────────────────────────────────────────────────────────
dev: ## Start full local dev stack
	$(DOCKER_COMPOSE) up -d postgres redis zookeeper kafka weaviate
	@echo "Waiting for services to be healthy..."
	@sleep 5
	$(DOCKER_COMPOSE) up backend celery_worker celery_beat kafka_consumer frontend

dev-build: ## Build and start all services
	$(DOCKER_COMPOSE) build
	$(MAKE) dev

down: ## Stop all services
	$(DOCKER_COMPOSE) down

down-volumes: ## Stop all services and remove volumes
	$(DOCKER_COMPOSE) down -v

logs: ## Tail logs for all services
	$(DOCKER_COMPOSE) logs -f

logs-backend: ## Tail backend logs
	$(DOCKER_COMPOSE) logs -f backend

logs-worker: ## Tail Celery worker logs
	$(DOCKER_COMPOSE) logs -f celery_worker

# ─── Database ─────────────────────────────────────────────────────────────────
migrate: ## Run Alembic migrations
	cd backend && alembic upgrade head

migrate-create: ## Create a new migration (usage: make migrate-create MSG="add column")
	cd backend && alembic revision --autogenerate -m "$(MSG)"

migrate-down: ## Downgrade one migration
	cd backend && alembic downgrade -1

# ─── Testing ──────────────────────────────────────────────────────────────────
test: ## Run all tests
	cd backend && $(PYTHON) -m pytest tests/ -v

test-cov: ## Run tests with coverage report
	cd backend && $(PYTHON) -m pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing

test-unit: ## Run unit tests only
	cd backend && $(PYTHON) -m pytest tests/unit/ -v

test-integration: ## Run integration tests only
	cd backend && $(PYTHON) -m pytest tests/integration/ -v -m integration

test-watch: ## Run tests in watch mode
	cd backend && $(PYTHON) -m pytest tests/ -v --watch

# ─── Code Quality ─────────────────────────────────────────────────────────────
lint: ## Run ruff linter
	cd backend && ruff check app/ tests/
	cd frontend && npm run lint

format: ## Format code with ruff + black
	cd backend && ruff format app/ tests/
	cd backend && ruff check --fix app/ tests/
	cd frontend && npm run format

typecheck: ## Run mypy type checking
	cd backend && mypy app/ --ignore-missing-imports

# ─── Workers ──────────────────────────────────────────────────────────────────
worker: ## Start Celery worker locally
	cd backend && celery -A app.workers.celery_app worker --loglevel=info --concurrency=2 -Q pr_review,default

beat: ## Start Celery beat scheduler
	cd backend && celery -A app.workers.celery_app beat --loglevel=info

consumer: ## Start Kafka consumer
	cd backend && $(PYTHON) -m app.kafka.consumer

flower: ## Start Celery Flower monitoring
	cd backend && celery -A app.workers.celery_app flower --port=5555

# ─── Frontend ─────────────────────────────────────────────────────────────────
frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-dev: ## Start frontend dev server
	cd frontend && npm run dev

frontend-build: ## Build frontend for production
	cd frontend && npm run build

frontend-preview: ## Preview production build
	cd frontend && npm run preview

# ─── Infrastructure ───────────────────────────────────────────────────────────
tf-init: ## Initialize Terraform
	cd infra/terraform && terraform init

tf-plan: ## Terraform plan
	cd infra/terraform && terraform plan -var-file=terraform.tfvars

tf-apply: ## Apply Terraform changes
	cd infra/terraform && terraform apply -var-file=terraform.tfvars

tf-destroy: ## Destroy Terraform infrastructure
	cd infra/terraform && terraform destroy -var-file=terraform.tfvars

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f infra/k8s/

helm-deploy: ## Deploy via Helm
	helm upgrade --install code-review infra/helm \
		-f infra/helm/values.prod.yaml \
		--set global.image.tag=$$(git rev-parse --short HEAD)

# ─── Utilities ────────────────────────────────────────────────────────────────
install: ## Install Python dependencies
	cd backend && $(PIP) install -r requirements.txt

shell: ## Open Python shell in backend context
	cd backend && $(PYTHON) -c "import asyncio; import app"

psql: ## Connect to PostgreSQL
	docker exec -it $$($(DOCKER_COMPOSE) ps -q postgres) psql -U codereview codereview

redis-cli: ## Connect to Redis
	docker exec -it $$($(DOCKER_COMPOSE) ps -q redis) redis-cli

health: ## Check service health
	curl -s http://localhost:8000/health | python3 -m json.tool

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
