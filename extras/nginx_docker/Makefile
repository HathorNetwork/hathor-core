.PHONY: all
all: docker

docker_tag = latest

.PHONY: docker
docker: nginx.conf
	docker build -t 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:$(docker_tag) .

.PHONY: docker-push
docker-push: docker
	docker push 769498303037.dkr.ecr.us-east-1.amazonaws.com/webtank:$(docker_tag)

.PHONY: run
run: docker
	docker run --link=fullnode -p 8000:80 -it hathor-nginx

nginx.conf:
	python -m hathor generate_nginx_config nginx.conf

.PHONY: clean
clean:
	rm -f nginx.conf
