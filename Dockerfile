# before changing these variables, make sure the tag $PYTHON_VERSION-alpine$ALPINE_VERSION exists first
# list of valid tags hese: https://hub.docker.com/_/python
ARG PYTHON_VERSION=3.6
ARG ALPINE_VERSION=3.12

# stage-0: copy pyproject.toml/poetry.lock and install the production set of dependencies
FROM python:$PYTHON_VERSION-alpine$ALPINE_VERSION as stage-0
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
# XXX: adding rocksdb and rocksdb-dev separately allows reuse of the rocksdb only
# XXX: keeping these together (no COPY from project in between) makes the installation
#      always consistent in case rocksdb is updated on the alpine repository (I had a
#      case where it was updated and "add rocksdb" layer was reused by "add rocksdb-dev" was not,
#      making the python binding try to load the updated lib, this pattern will prevent that)
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN apk add openssl-dev libffi-dev build-base
RUN pip install poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
COPY pyproject.toml poetry.lock  ./
RUN poetry install -n -E rocksdb --no-root --no-dev

# stage-1: install all dev dependencies and build protos, reuse .venv from stage-0
FROM python:$PYTHON_VERSION-alpine$ALPINE_VERSION as stage-1
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN apk add openssl-dev libffi-dev build-base
RUN pip install poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
COPY pyproject.toml poetry.lock  ./
COPY --from=stage-0 /usr/src/app/.venv /usr/src/app/.venv/
RUN poetry install -n -E rocksdb --no-root
COPY Makefile ./
COPY hathor/protos ./hathor/protos/
RUN poetry run make protos

# finally: use production .venv (from stage-0) and compiled protos (from stage-1)
# lean and mean: this image should be about ~110MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON_VERSION-alpine$ALPINE_VERSION
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
COPY --from=stage-0 /usr/src/app/.venv/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=stage-1 /usr/src/app/hathor/protos/*.py /usr/src/app/hathor/protos/
COPY hathor ./hathor
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
