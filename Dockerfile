# before changing these variables, make sure the tag $PYTHON-alpine$ALPINE exists first
# list of valid tags hese: https://hub.docker.com/_/python
# XXX: docker.io/python images use a `ENV PYTHON_VERSION` that would shadow an ARG of same name
ARG PYTHON=3.7
ARG ALPINE=3.13

# stage-0: copy pyproject.toml/poetry.lock and install the production set of dependencies
FROM python:$PYTHON-alpine$ALPINE as stage-0
ARG PYTHON
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
# XXX: adding rocksdb and rocksdb-dev separately allows reuse of the rocksdb only
# XXX: keeping these together (no COPY from project in between) makes the installation
#      always consistent in case rocksdb is updated on the alpine repository (I had a
#      case where it was updated and "add rocksdb" layer was reused by "add rocksdb-dev" was not,
#      making the python binding try to load the updated lib, this pattern will prevent that)
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN apk add openssl-dev libffi-dev build-base rust cargo
RUN pip --no-input --no-cache-dir install --upgrade pip poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
COPY pyproject.toml poetry.lock  ./
RUN poetry install -n -E rocksdb --no-root --no-dev

# stage-1: install all dev dependencies and build protos, reuse .venv from stage-0
FROM python:$PYTHON-alpine$ALPINE as stage-1
ARG PYTHON
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN apk add openssl-dev libffi-dev build-base rust cargo
RUN pip --no-input --no-cache-dir install --upgrade pip poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
COPY pyproject.toml poetry.lock  ./
RUN poetry install -n -E rocksdb --no-root --no-dev
# up to the line above is be the same as in stage-0, and thus all layers are re-used
RUN poetry install -n -E rocksdb --no-root
COPY Makefile ./
COPY hathor/protos ./hathor/protos/
RUN make clean-protos
RUN poetry run make protos

# finally: use production .venv (from stage-0) and compiled protos (from stage-1)
# lean and mean: this image should be about ~110MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON-alpine$ALPINE
ARG PYTHON
WORKDIR /usr/src/app/
RUN apk add --no-cache openssl libffi graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
COPY --from=stage-0 /usr/src/app/.venv/lib/python${PYTHON}/site-packages /usr/local/lib/python${PYTHON}/site-packages
COPY --from=stage-1 /usr/src/app/hathor/protos/*.py /usr/src/app/hathor/protos/
COPY hathor ./hathor
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
