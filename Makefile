.PHONY: dev prod test launch launch-down down logs migrate worker

dev:
	docker compose --profile dev up --build api-dev

prod:
	docker compose --profile prod up --build -d api-prod

test:
	docker compose --profile test run --rm api-test

launch:
	docker compose --profile launch up --build -d postgres keycloak kong ollama api-launch api-worker

launch-down:
	docker compose --profile launch down

migrate:
	alembic upgrade head

worker:
	python -m app.worker

down:
	docker compose down

logs:
	docker compose logs -f
