.PHONY: help install dev lint fmt test test-unit test-cov scan docker-build docker-scan clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install package
	pip install -e .

dev:  ## Install with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

lint:  ## Run linter
	ruff check src/ tests/

fmt:  ## Auto-format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

test:  ## Run all unit tests
	pytest -m unit -v

test-unit:  ## Run unit tests only (alias)
	pytest -m unit -v

test-cov:  ## Run tests with coverage report
	pytest -m unit --cov --cov-report=term-missing --cov-report=html

scan:  ## Run SSPM scan (requires env vars)
	tableau-sspm --output-dir ./sspm_output

docker-build:  ## Build Docker image
	docker build -t tableau-sspm:latest .

docker-scan:  ## Run scan via Docker (requires env vars)
	docker run --rm \
		-e TABLEAU_SERVER \
		-e TABLEAU_SITE \
		-e TABLEAU_TOKEN_NAME \
		-e TABLEAU_TOKEN_SECRET \
		-v $$(pwd)/sspm_output:/app/output \
		tableau-sspm:latest

clean:  ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf sspm_output/
