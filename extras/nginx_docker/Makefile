.PHONY: all
all: docker

tag = 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:latest

.PHONY: docker
docker: nginx.conf set_real_ip_from_cloudfront
	docker build -t $(tag) .

.PHONY: docker-push
docker-push: docker
	docker push $(tag)

.PHONY: run
run: docker
	docker run --rm --link=fullnode -p 8000:80 -it $(tag)

nginx.conf:
	python -m hathor generate_nginx_config nginx.conf

set_real_ip_from_cloudfront:
	curl https://ip-ranges.amazonaws.com/ip-ranges.json -s \
	| jq '.prefixes|map(select(.service=="CLOUDFRONT"))[]|.ip_prefix' -r \
	| sort -h \
	| xargs -n 1 printf "set_real_ip_from %s;\n" \
	> $@

.PHONY: clean
clean:
	rm -f nginx.conf set_real_ip_from_cloudfront
