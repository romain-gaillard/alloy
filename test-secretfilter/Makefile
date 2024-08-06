.PHONY: up
up: reset/env # First resets everything to make sure we have a clean environment and re-ingest the logs
	docker-compose up

.PHONY: down
down: down
	docker-compose down

.PHONY: reset/env
reset/env: down
	docker system prune -f --filter label='com.grafana.secret-filtering-alloy.env=development' --all --volumes
