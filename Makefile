.PHONY: help install dev lint test security run clean docker-build docker-up docker-down audit-verify inventory

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -e .

dev: ## Install all dependencies (dev + cli)
	pip install -e ".[dev,cli]"
	pre-commit install

lint: ## Run linter and type checker
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/ai_governance/

format: ## Auto-format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

test: ## Run tests with coverage
	pytest

security: ## Run security scans (Bandit + pip-audit)
	bandit -r src/ai_governance/
	pip-audit --strict

run: ## Start the proxy for local development (no TLS or keys required; never use with real data)
	ALLOW_INSECURE_DEV=true uvicorn ai_governance.server:app --host 127.0.0.1 --port 8000 --reload

serve: ## Start the proxy the way production does (needs PROXY_API_KEYS, AUDIT_HMAC_KEY and TLS settings)
	ai-gov-server

demo: ## Run the CLI demo
	python -m ai_governance.cli.demo

docker-build: ## Build the Docker image
	docker build -f docker/Dockerfile -t ai-governance:latest .

docker-up: ## Start the Docker Compose stack
	cd docker && docker compose up -d

docker-down: ## Stop the Docker Compose stack
	cd docker && docker compose down

audit-verify: ## Verify audit log integrity
	python -c "from ai_governance.audit.logger import AuditLogger; from pathlib import Path; a = AuditLogger(Path('audit_logs/governance.jsonl')); v, c = a.verify_chain(); print(f'Valid: {v}, Entries: {c}')"

inventory: ## Check the AI use case inventory
	ai-gov-inventory

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
