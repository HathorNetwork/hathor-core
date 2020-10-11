py_sources = hathor/ tests/

.PHONY: all
all: check tests

# testing:

tests_simulation = tests/simulation/
tests_cli = tests/cli/
tests_lib = $(filter-out ${tests_cli} ${tests_simulation} tests/__pycache__/, $(dir $(wildcard tests/*/.)))

pytest_flags = -p no:warnings --cov-report=term --cov-report=html --cov-report=xml --cov=hathor
mypy_flags = --warn-unused-configs --disallow-incomplete-defs --no-implicit-optional --warn-redundant-casts --warn-unused-ignores

#--strict-equality
#--check-untyped-defs

#--disallow-untyped-defs
#--disallow-any-generics
#--disallow-subclassing-any
#--warn-return-any
#--disallow-untyped-calls
#--disallow-untyped-decorators

#--implicit-reexport
#--no-implicit-reexport

.PHONY: tests-cli
tests-cli:
	pytest --durations=10 --cov=hathor/cli/ --cov-config=.coveragerc_full --cov-fail-under=30 -p no:warnings $(tests_cli)

.PHONY: tests-doctests
tests-doctests:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor

.PHONY: tests-lib
tests-lib:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor --cov-fail-under=83 $(tests_lib)

.PHONY: tests-simulation
tests-simulation:
	pytest --durations=10 --cov=hathor --cov-report=term -p no:warnings $(tests_simulation)

.PHONY: tests-genesis
tests-genesis:
	HATHOR_TEST_CONFIG_FILE=hathor.conf.mainnet pytest tests/tx/test_genesis.py
	HATHOR_TEST_CONFIG_FILE=hathor.conf.testnet pytest tests/tx/test_genesis.py

.PHONY: tests
tests: tests-cli tests-lib tests-genesis

.PHONY: tests-full
tests-full:
	pytest $(pytest_flags) --durations=10 --cov-fail-under=90 --cov-config=.coveragerc_full ./tests

# checking:

.PHONY: mypy
mypy:
	mypy $(mypy_flags) ./hathor

.PHONY: flake8
flake8:
	flake8 $(py_sources)

.PHONY: isort-check
isort-check:
	isort -ac -rc --check-only $(py_sources)

.PHONY: check
check: flake8 isort-check mypy

# formatting:

.PHONY: fmt
fmt: yapf isort

.PHONY: yapf
yapf:
	yapf -rip $(py_sources) -e \*_pb2.py,\*_pb2_grpc.py

.PHONY: isort
isort:
	isort -ac -rc $(py_sources)

# generation:

proto_dir = ./hathor/protos
proto_srcs = $(wildcard $(proto_dir)/*.proto)
proto_outputs = $(patsubst %.proto,%_pb2.py,$(proto_srcs)) $(patsubst %.proto,%_pb2_grpc.py,$(proto_srcs)) $(patsubst %.proto,%_pb2.pyi,$(proto_srcs))
GRPC_TOOLS_VERSION = "$(shell python -m grpc_tools.protoc --version 2>/dev/null || true)"
#ifdef GRPC_TOOLS_VERSION
ifneq ($(GRPC_TOOLS_VERSION),"")
	protoc := python -m grpc_tools.protoc
else
	protoc := protoc
endif

# all proto_srcs are added as deps so when a change on any of them triggers all to be rebuilt
%_pb2.pyi %_pb2.py: %.proto $(proto_srcs)
	$(protoc) -I. --python_out=. --mypy_out=. $<
%_pb2_grpc.py: %.proto $(proto_srcs)
	$(protoc) -I. --grpc_python_out=. $< || true

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

.PHONY: clean-caches
clean-caches:
	rm -rf .coverage .mypy_cache .pytest_cache coverage.xml coverage_html_report

.PHONY: clean
clean: clean-pyc clean-protos clean-caches

# docker:

docker_dir := .
ifdef GITHUB_REF
	docker_subtag := $(GITHUB_REF)
else
ifneq ($(wildcard .git/.*),)
	docker_subtag := $(shell git describe --tags --dirty)
else
	docker_subtag := $(shell date +'%y%m%d%H%M%S')
endif
endif
docker_tag := hathor-core:$(docker_subtag)
docker_build_arg :=
docker_build_flags :=
ifneq ($(docker_build_arg),)
	docker_build_flags +=  --build-arg $(docker_build_arg)
endif

.PHONY: docker
docker: $(docker_dir)/Dockerfile $(proto_outputs)
	docker build$(docker_build_flags) -t $(docker_tag) $(docker_dir)

.PHONY: docker-push
docker-push: docker
	docker tag $(docker_tag) hathornetwork/hathor-core:$(docker_subtag)
	docker push hathornetwork/hathor-core:$(docker_subtag)

.PHONY: docker-push
docker-push-aws: docker
	docker tag $(docker_tag) 769498303037.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_subtag)
	docker push 769498303037.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_subtag)
