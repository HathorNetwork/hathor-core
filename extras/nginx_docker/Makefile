.PHONY: all
all: docker

tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:latest
no_rate_limit_tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:no-rate-limit-latest

.PHONY: docker
docker: docker-default docker-no-rate-limit

# Default Nginx Image
.PHONY: docker-default
docker-default: nginx.conf set_real_ip_from_cloudfront
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(tag) .

nginx.conf: export PYTHONPATH := ../..
nginx.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config - > $@

# Nginx Image used for private use cases, with rate limits disabled
.PHONY: docker-no-rate-limit
docker-no-rate-limit: nginx_no_rate_limit.conf set_real_ip_from_cloudfront
	mv nginx_no_rate_limit.conf nginx.conf
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(no_rate_limit_tag) .

nginx_no_rate_limit.conf: export PYTHONPATH := ../..
nginx_no_rate_limit.conf:
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
