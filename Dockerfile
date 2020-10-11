# before changing these variables, make sure the tag $PYTHON_VERSION-alpine$ALPINE_VERSION exists first
# list of valid tags hese: https://hub.docker.com/_/python
ARG PYTHON_VERSION=3.6
ARG ALPINE_VERSION=3.12

# stage-0: install all python deps, build and install package, everything will be available on .venv
FROM python:$PYTHON_VERSION-alpine$ALPINE_VERSION as stage-0
# install runtime first deps to speedup the dev deps and because layers will be reused on stage-1
RUN apk add --no-cache openssl libffi libstdc++ graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
# dev deps for this build start here
RUN apk add openssl-dev libffi-dev build-base git
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev
RUN pip install --no-cache-dir poetry
# monkeypatch poetry to disable parallel execution that on resource limited hosts (like GitHub runners) can
# hang (ReadTimeout) downloads while heavy jobs (packages that need compiling) are running in parallel
RUN sed -i '/__init__/s/parallel=True/parallel=False/' /usr/local/lib/python*/site-packages/poetry/installation/executor.py
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
WORKDIR /app/
COPY pyproject.toml poetry.lock  ./
# rocksdb takes the longest to build and install, we pre-install it separetely to help slow hosts get
# through `poetry install` without timing-out (which is the case for arm64 that runs on qemu on github-runner)
RUN poetry run pip install 'python-rocksdb==0.7.0'
RUN poetry install -n -E rocksdb --no-root --no-dev
COPY hathor ./hathor
COPY README.md .
RUN poetry build -n -f wheel
RUN poetry run pip install --compile --no-deps --quiet --no-input dist/*.whl

# finally: use production .venv from before
# lean and mean: this image should be about ~50MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON_VERSION-alpine$ALPINE_VERSION
RUN apk add --no-cache openssl libffi libstdc++ graphviz
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
COPY --from=stage-0 /app/.venv/lib/ /usr/local/lib/
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
