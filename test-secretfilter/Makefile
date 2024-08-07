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
	echo "Please put the model files (spago_model.bin, config.json, merges.txt, vocab.json) in the model directory"
	exit 1
endif
