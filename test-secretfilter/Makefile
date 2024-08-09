.PHONY: up
up: download-model
	docker compose up

.PHONY: up-build
up-build: download-model
	docker compose build 
	docker compose up --force-recreate

.PHONY: down
down:
	docker compose down

.PHONY: reset/env
reset/env: down
	docker system prune -f --filter label='com.grafana.secret-filtering-alloy.env=development' --all --volumes

.PHONY: download-model
download-model:
ifeq (,$(wildcard ./model/spago_model.bin))
	echo "Please put the model files (spago_model.bin, config.json, merges.txt, vocab.json) in the model directory"
	exit 1
endif
