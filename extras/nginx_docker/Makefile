.PHONY: all
all: help

DEFAULT_LATEST_TAG = latest
DEFAULT_NO_RATE_LIMIT_TAG = no-rate-limit-latest

# Build and Push Commands
# =======================

# GCP / Hathor Testnet
HATHOR_TESTNET_REGISTRY = us-central1-docker.pkg.dev/hathor-testnet/fullnodes/webtank

HATHOR_TESTNET_INDIA_TAG_LATEST = india-latest
HATHOR_TESTNET_INDIA_TAG_NO_RATE_LIMIT = india-no-rate-limit-latest

.PHONY: hathor-testnet
hathor-testnet: hathor-testnet-default hathor-testnet-no-rate-limit hathor-testnet-india-default hathor-testnet-india-no-rate-limit
	@echo "All Hathor Testnet images built and pushed successfully!"

.PHONY: hathor-testnet-default
hathor-testnet-default: clean nginx.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for Hathor Testnet..."
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: hathor-testnet-no-rate-limit
hathor-testnet-no-rate-limit: clean nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for Hathor Testnet..."
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

.PHONY: hathor-testnet-india-default
hathor-testnet-india-default: clean nginx_india.conf set_real_ip_from_cloudfront
	@echo "Building and pushing india image for Hathor Testnet..."
	mv nginx_india.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_REGISTRY):$(HATHOR_TESTNET_INDIA_TAG_LATEST) .

.PHONY: hathor-testnet-india-no-rate-limit
hathor-testnet-india-no-rate-limit: clean nginx_india_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit india image for Hathor Testnet..."
	mv nginx_india_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_REGISTRY):$(HATHOR_TESTNET_INDIA_TAG_NO_RATE_LIMIT) .

# GCP / Nano Testnet
NANO_TESTNET_REGISTRY = us-central1-docker.pkg.dev/nano-testnet/fullnodes/webtank

NANO_TESTNET_BRAVO_TAG_LATEST = bravo-latest
NANO_TESTNET_BRAVO_TAG_NO_RATE_LIMIT = bravo-no-rate-limit-latest

.PHONY: nano-testnet
nano-testnet: nano-testnet-default nano-testnet-no-rate-limit nano-testnet-bravo-default nano-testnet-bravo-no-rate-limit
	@echo "All Nano Testnet images built and pushed successfully!"

.PHONY: nano-testnet-default
nano-testnet-default: clean nginx.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for Nano Testnet..."
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(NANO_TESTNET_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: nano-testnet-no-rate-limit
nano-testnet-no-rate-limit: clean nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for Nano Testnet..."
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(NANO_TESTNET_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

.PHONY: nano-testnet-bravo-default
nano-testnet-bravo-default: clean nginx_bravo.conf set_real_ip_from_cloudfront
	@echo "Building and pushing bravo image for Nano Testnet..."
	mv nginx_bravo.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(NANO_TESTNET_REGISTRY):$(NANO_TESTNET_BRAVO_TAG_LATEST) .

.PHONY: nano-testnet-bravo-no-rate-limit
nano-testnet-bravo-no-rate-limit: clean nginx_bravo_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit bravo image for Nano Testnet..."
	mv nginx_bravo_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(NANO_TESTNET_REGISTRY):$(NANO_TESTNET_BRAVO_TAG_NO_RATE_LIMIT) .

# GCP / Standalone Fullnodes
STANDALONE_FULLNODES_REGISTRY = us-central1-docker.pkg.dev/standalone-fullnodes/fullnodes/webtank

.PHONY: standalone-fullnodes
standalone-fullnodes: standalone-fullnodes-default standalone-fullnodes-no-rate-limit
	@echo "All Standalone Fullnodes images built and pushed successfully!"

.PHONY: standalone-fullnodes-default
standalone-fullnodes-default: clean nginx.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for Standalone Fullnodes..."
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(STANDALONE_FULLNODES_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: standalone-fullnodes-no-rate-limit
standalone-fullnodes-no-rate-limit: clean nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for Standalone Fullnodes..."
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(STANDALONE_FULLNODES_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

# GCP / Ekvilibro
EKVILIBRO_REGISTRY = us-central1-docker.pkg.dev/ekvilibro/fullnodes/webtank

.PHONY: ekvilibro
ekvilibro: ekvilibro-default ekvilibro-no-rate-limit
	@echo "All Ekvilibro images built and pushed successfully!"

.PHONY: ekvilibro-default
ekvilibro-default: clean nginx.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for Ekvilibro..."
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(EKVILIBRO_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: ekvilibro-no-rate-limit
ekvilibro-no-rate-limit: clean nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for Ekvilibro..."
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(EKVILIBRO_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

# GCP / Hathor Testnet Playground
HATHOR_TESTNET_PLAYGROUND_REGISTRY = us-central1-docker.pkg.dev/hathor-testnet-playground/fullnodes/webtank

.PHONY: hathor-testnet-playground
hathor-testnet-playground: hathor-testnet-playground-default hathor-testnet-playground-no-rate-limit
	@echo "All Hathor Testnet Playground images built and pushed successfully!"

.PHONY: hathor-testnet-playground-default
hathor-testnet-playground-default: clean nginx_playground.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for Hathor Testnet Playground..."
	mv nginx_playground.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_PLAYGROUND_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: hathor-testnet-playground-no-rate-limit
hathor-testnet-playground-no-rate-limit: clean nginx_playground_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for Hathor Testnet Playground..."
	mv nginx_playground_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(HATHOR_TESTNET_PLAYGROUND_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

# AWS / Main Account
AWS_MAIN_REGISTRY = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank

.PHONY: aws-main
aws-main: aws-main-default aws-main-no-rate-limit
	@echo "All AWS Main images built and pushed successfully!"

.PHONY: aws-main-default
aws-main-default: clean nginx.conf set_real_ip_from_cloudfront
	@echo "Building and pushing latest image for AWS Main..."
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(AWS_MAIN_REGISTRY):$(DEFAULT_LATEST_TAG) .

.PHONY: aws-main-no-rate-limit
aws-main-no-rate-limit: clean nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	@echo "Building and pushing no-rate-limit image for AWS Main..."
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(AWS_MAIN_REGISTRY):$(DEFAULT_NO_RATE_LIMIT_TAG) .

# Build All (convenience command)
.PHONY: build-all
build-all: hathor-testnet nano-testnet standalone-fullnodes ekvilibro hathor-testnet-playground aws-main
	@echo "All images built and pushed successfully!"

# Legacy commands for backward compatibility
.PHONY: docker
docker: aws-main

.PHONY: docker-default
docker-default: aws-main-default

.PHONY: docker-no-rate-limit
docker-no-rate-limit: aws-main-no-rate-limit

# Configuration Generation
# ========================

nginx.conf: export PYTHONPATH := ../..
nginx.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config - > $@

nginx_no_rate_limit.conf: export PYTHONPATH := ../..
nginx_no_rate_limit.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --disable-rate-limits - > $@

nginx_bravo.conf: export PYTHONPATH := ../..
nginx_bravo.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override nano-testnet-bravo - > $@

nginx_bravo_no_rate_limit.conf: export PYTHONPATH := ../..
nginx_bravo_no_rate_limit.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override nano-testnet-bravo --disable-rate-limits - > $@

nginx_india.conf: export PYTHONPATH := ../..
nginx_india.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override hathor-testnet-india - > $@

nginx_india_no_rate_limit.conf: export PYTHONPATH := ../..
nginx_india_no_rate_limit.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override hathor-testnet-india --disable-rate-limits - > $@

nginx_playground.conf: export PYTHONPATH := ../..
nginx_playground.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override hathor-testnet-playground - > $@

nginx_playground_no_rate_limit.conf: export PYTHONPATH := ../..
nginx_playground_no_rate_limit.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --override hathor-testnet-playground --disable-rate-limits - > $@

set_real_ip_from_cloudfront:
	curl https://ip-ranges.amazonaws.com/ip-ranges.json -s \
	| jq '.prefixes|map(select(.service=="CLOUDFRONT"))[]|.ip_prefix' -r \
	| sort -h \
	| xargs -n 1 printf "set_real_ip_from %s;\n" \
	> $@

# Utility Commands
# ===============

.PHONY: clean
clean:
	rm -f nginx.conf nginx_no_rate_limit.conf nginx_bravo.conf nginx_bravo_no_rate_limit.conf nginx_india.conf nginx_india_no_rate_limit.conf set_real_ip_from_cloudfront

.PHONY: help
help:
	@echo "Available commands:"
	@echo ""
	@echo "Project/Account Commands:"
	@echo "  hathor-testnet             		- Build and push all images for GCP Project Hathor Testnet"
	@echo "  hathor-testnet-default     		- Build and push default image for GCP Project Hathor Testnet"
	@echo "  hathor-testnet-no-rate-limit		- Build and push no-rate-limit image for GCP Project Hathor Testnet"
	@echo "  hathor-testnet-india-default		- Build and push india image for GCP Project Hathor Testnet"
	@echo "  hathor-testnet-india-no-rate-limit - Build and push no-rate-limit india image for GCP Project Hathor Testnet"
	@echo "  nano-testnet              			- Build and push all images for GCP Project Nano Testnet"
	@echo "  nano-testnet-default      			- Build and push default image for GCP Project Nano Testnet"
	@echo "  nano-testnet-no-rate-limit 		- Build and push no-rate-limit image for GCP Project Nano Testnet"
	@echo "  nano-testnet-bravo-default 		- Build and push bravo image for GCP Project Nano Testnet"
	@echo "  nano-testnet-bravo-no-rate-limit 	- Build and push no-rate-limit bravo image for GCP Project Nano Testnet"
	@echo "  standalone-fullnodes	   			- Build and push all images for GCP Project Standalone Fullnodes"
	@echo "  standalone-fullnodes-default 		- Build and push default image for GCP Project Standalone Fullnodes"
	@echo "  standalone-fullnodes-no-rate-limit - Build and push no-rate-limit image for GCP Project Standalone Fullnodes"
	@echo "  ekvilibro                 			- Build and push all images for GCP Project Ekvilibro"
	@echo "  ekvilibro-default         			- Build and push default image for GCP Project Ekvilibro"
	@echo "  ekvilibro-no-rate-limit   			- Build and push no-rate-limit image for GCP Project Ekvilibro"
	@echo "  hathor-testnet-playground                 - Build and push all images for GCP Project Hathor Testnet Playground"
	@echo "  hathor-testnet-playground-default         - Build and push default image for GCP Project Hathor Testnet Playground"
	@echo "  hathor-testnet-playground-no-rate-limit   - Build and push no-rate-limit image for GCP Project Hathor Testnet Playground"
	@echo "  aws-main                  			- Build and push all images for AWS Main Account"
	@echo "  aws-main-default          			- Build and push default image for AWS Main Account"
	@echo "  aws-main-no-rate-limit	  			- Build and push no-rate-limit image for AWS Main Account"
	@echo ""
	@echo "Utility Commands:"
	@echo "  build-all                 - Build and push all active project images"
	@echo "  clean                     - Remove generated files"
	@echo "  help                      - Show this help message"
	@echo ""
	@echo "Legacy Commands (for backward compatibility):"
	@echo "  docker                    - Alias for aws-main"
	@echo "  docker-default            - Alias for aws-main-default"
	@echo "  docker-no-rate-limit      - Alias for aws-main-no-rate-limit"
	@echo ""
	@echo "Supported Projects/Accounts:"
	@echo "  - Hathor Testnet: $(HATHOR_TESTNET_REGISTRY)"
	@echo "  - Nano Testnet: $(NANO_TESTNET_REGISTRY)"
	@echo "  - Standalone Fullnodes: $(STANDALONE_FULLNODES_REGISTRY)"
	@echo "  - Ekvilibro: $(EKVILIBRO_REGISTRY)"
	@echo "  - Hathor Testnet Playground: $(HATHOR_TESTNET_PLAYGROUND_REGISTRY)"
	@echo "  - AWS Main Account: $(AWS_MAIN_REGISTRY)"
	@echo ""
