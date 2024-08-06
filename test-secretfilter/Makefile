.PHONY: up-nobuild
up-nobuild: reset/env
	docker-compose up

.PHONY: up
up: reset/env
	docker-compose build --no-cache
	docker-compose up --force-recreate

.PHONY: down
down: down
	docker-compose down

.PHONY: reset/env
reset/env: down
	docker system prune -f --filter label='com.grafana.secret-filtering-alloy.env=development' --all --volumes
