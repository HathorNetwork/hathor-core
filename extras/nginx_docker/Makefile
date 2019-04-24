.PHONY: all
all: docker

docker_tag = latest

.PHONY: docker
docker: nginx.conf
	docker build -t hathor-nginx:$(docker_tag) .

.PHONY: docker-push
docker-push: docker
	#docker tag fullnode:$(docker_tag) 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_tag)
	#docker push 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_tag)
	docker tag hathor-nginx:$(docker_tag) 537254410709.dkr.ecr.us-east-1.amazonaws.com/webtank:latest
	docker push 537254410709.dkr.ecr.us-east-1.amazonaws.com/webtank:latest

.PHONY: run
run: docker
	docker run --link=fullnode -p 8000:80 -it hathor-nginx

nginx.conf:
	hathor-cli generate_nginx_config nginx.conf

.PHONY: clean
clean:
	rm -f nginx.conf
