.PHONY: all
all: docker

tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:latest

.PHONY: docker
docker: nginx.conf set_real_ip_from_cloudfront
	docker buildx build --pull --push --platform linux/arm64/v8,linux/amd64 --tag $(tag) .

nginx.conf: export PYTHONPATH := ../..
nginx.conf:
	@python -c "import os; import hathor; print('Using hathor-core from:', os.path.dirname(hathor.__file__))"
	python -m hathor generate_nginx_config - > $@

set_real_ip_from_cloudfront:
	curl https://ip-ranges.amazonaws.com/ip-ranges.json -s \
	| jq '.prefixes|map(select(.service=="CLOUDFRONT"))[]|.ip_prefix' -r \
	| sort -h \
	| xargs -n 1 printf "set_real_ip_from %s;\n" \
	> $@

.PHONY: clean
clean:
	rm -f nginx.conf set_real_ip_from_cloudfront
