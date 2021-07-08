.PHONY: all
all: docker

tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:latest
use_cases_tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:use-cases-latest

.PHONY: docker
docker: docker-default docker-use-cases

# Default Nginx Image
.PHONY: docker-default
docker-default: nginx.conf set_real_ip_from_cloudfront
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(tag) .

nginx.conf: export PYTHONPATH := ../..
nginx.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config - > $@

# Nginx Image used for private use cases, with rate limits disabled
.PHONY: docker-use-cases
docker-use-cases: nginx_use_cases.conf set_real_ip_from_cloudfront
	mv nginx_use_cases.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(use_cases_tag) .

nginx_use_cases.conf: export PYTHONPATH := ../..
nginx_use_cases.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config --disable-rate-limits - > $@

set_real_ip_from_cloudfront:
	curl https://ip-ranges.amazonaws.com/ip-ranges.json -s \
	| jq '.prefixes|map(select(.service=="CLOUDFRONT"))[]|.ip_prefix' -r \
	| sort -h \
	| xargs -n 1 printf "set_real_ip_from %s;\n" \
	> $@

.PHONY: clean
clean:
	rm -f nginx.conf set_real_ip_from_cloudfront
