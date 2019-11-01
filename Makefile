py_sources = hathor/ tests/ tools/ $(wildcard *.py)

.PHONY: all
all: check tests

# testing:

tests_simulation = tests/simulation/
tests_cli = tests/cli/
tests_lib = $(filter-out ${tests_cli} ${tests_simulation} tests/__pycache__/, $(dir $(wildcard tests/*/.)))

pytest_flags = -p no:warnings --cov-report=term --cov-report=html --cov=hathor

.PHONY: tests-cli
tests-cli:
	pytest --durations=10 --cov=hathor/cli/ --cov-config=.coveragerc_full --cov-fail-under=61 -p no:warnings $(tests_cli)

.PHONY: tests-doctests
tests-doctests:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor

.PHONY: tests-lib
tests-lib:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor --cov-fail-under=88 $(tests_lib)

.PHONY: tests-simulation
tests-simulation:
	pytest --durations=10 --cov=hathor --cov-report=term -p no:warnings $(tests_simulation)

.PHONY: tests
tests: tests-cli tests-lib

.PHONY: tests-full
tests-full:
	pytest $(pytest_flags) --durations=10 --cov-fail-under=90 --cov-config=.coveragerc_full ./tests

# checking:

.PHONY: mypy
mypy: ./hathor
	mypy $^

.PHONY: flake8
flake8: $(py_sources)
	flake8 $^

.PHONY: isort-check
isort-check: $(py_sources)
	isort -ac -rc --check-only $^

.PHONY: check
check: flake8 isort-check mypy

# formatting:

.PHONY: fmt
fmt: yapf isort

.PHONY: yapf
yapf: $(py_sources)
	yapf -rip $^ -e \*_pb2.py,\*_pb2_grpc.py

.PHONY: isort
isort: $(py_sources)
	isort -ac -rc $^

# generation:

proto_dir = ./hathor/protos
proto_srcs = $(wildcard $(proto_dir)/*.proto)
proto_outputs = $(patsubst %.proto,%_pb2.py,$(proto_srcs)) $(patsubst %.proto,%_pb2_grpc.py,$(proto_srcs)) $(patsubst %.proto,%_pb2.pyi,$(proto_srcs))

# all proto_srcs are added as deps so we a change on any of them triggers all to be rebuilt
%_pb2.pyi %_pb2.py %_pb2_grpc.py: %.proto $(proto_srcs)
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. --mypy_out=. $<

.PHONY: protos
protos: $(proto_outputs)

# cleaning:

.PHONY: clean-protos
clean-protos:
	rm -f $(proto_outputs)

.PHONY: clean-pyc
clean-pyc:
	find hathor tests -name \*.pyc -delete
	find hathor tests -name __pycache__ -delete

.PHONY: clean
clean: clean-pyc clean-protos

# docker:

docker_dir := .
ifneq ($(wildcard .git/.*),)
	docker_tag := $(shell git describe)
else
	docker_tag := dummy
endif

.PHONY: docker
docker: $(docker_dir)/Dockerfile $(proto_outputs)
	docker build -t fullnode:$(docker_tag) $(docker_dir)

.PHONY: docker-push
docker-push: docker
	docker tag fullnode:$(docker_tag) 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_tag)
	docker push 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_tag)
	docker tag fullnode:$(docker_tag) 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:latest
	docker push 537254410709.dkr.ecr.us-east-1.amazonaws.com/fullnode:latest
