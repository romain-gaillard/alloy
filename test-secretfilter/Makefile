.PHONY: up
up: reset/env download-model
	docker-compose up

.PHONY: up-build
up-build: reset/env download-model
	docker-compose build --no-cache
	docker-compose up --force-recreate

.PHONY: down
down: down
	docker-compose down

.PHONY: reset/env
reset/env: down
	docker system prune -f --filter label='com.grafana.secret-filtering-alloy.env=development' --all --volumes

.PHONY: download-model
download-model:
ifeq (,$(wildcard ./model/spago_model.bin))
	curl -L "https://github.com/romain-gaillard/alloy/releases/download/model/model.zip" > model/output.zip
	unzip model/output.zip -d ./model/
	rm model/output.zip
endif
