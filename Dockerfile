# before changing these variables, make sure the tag $PYTHON-alpine$ALPINE exists first
# list of valid tags hese: https://hub.docker.com/_/python
# XXX: docker.io/python images use a `ENV PYTHON_VERSION` that would shadow an ARG of same name
ARG PYTHON=3.7
ARG ALPINE=3.15

# stage-0: copy pyproject.toml/poetry.lock and install the production set of dependencies
FROM python:$PYTHON-alpine$ALPINE as stage-0
ARG PYTHON
RUN apk add --no-cache openssl libffi graphviz
# XXX: adding rocksdb and rocksdb-dev separately allows reuse of the rocksdb only
# XXX: keeping these together (no COPY from project in between) makes the installation
#      always consistent in case rocksdb is updated on the alpine repository (I had a
#      case where it was updated and "add rocksdb" layer was reused by "add rocksdb-dev" was not,
#      making the python binding try to load the updated lib, this pattern will prevent that)
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN apk add openssl-dev libffi-dev build-base cargo git pkgconfig
RUN pip --no-input --no-cache-dir install --upgrade pip wheel poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
WORKDIR /app/
COPY pyproject.toml poetry.lock  ./
RUN poetry install -n -E sentry --no-root --no-dev
COPY hathor ./hathor
COPY README.md ./
RUN poetry build -f wheel
RUN poetry run pip install dist/hathor-*.whl

# stage-1: use production .venv (from stage-0)
# lean and mean: this image should be about ~110MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON-alpine$ALPINE
ARG PYTHON
RUN apk add --no-cache openssl libffi graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
COPY --from=stage-0 /app/.venv/lib/python${PYTHON}/site-packages/ /usr/local/lib/python${PYTHON}/site-packages/
COPY hathor ./hathor
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
