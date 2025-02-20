# before changing these variables, make sure the tag $PYTHON-alpine$ALPINE exists first
# list of valid tags hese: https://hub.docker.com/_/python
ARG PYTHON=3.11
ARG DEBIAN=bookworm

# use this image to copy uv binaries from
FROM ghcr.io/astral-sh/uv:python$PYTHON-bookworm-slim AS uv-bin
RUN uv -V
RUN uvx -V

# stage-0: copy pyproject.toml/poetry.lock and install the production set of dependencies
FROM python:$PYTHON-slim-$DEBIAN AS stage-0
ARG PYTHON
# install runtime first deps to speedup the dev deps and because layers will be reused on stage-1
RUN apt-get -qy update
#RUN apt-get -qy install libssl1.1 graphviz librocksdb6.11
RUN apt-get -qy install libssl3 graphviz librocksdb7.8
# dev deps for this build start here
RUN apt-get -qy install libssl-dev libffi-dev build-essential zlib1g-dev libbz2-dev libsnappy-dev liblz4-dev librocksdb-dev cargo git pkg-config
COPY --from=uv-bin /usr/local/bin/uv /usr/local/bin/uvx /bin/
# install all deps in a virtualenv so we can just copy it over to the final image
WORKDIR /app/
COPY pyproject.toml uv.lock  ./
#RUN uv pip install --extra sentry -e .
COPY hathor ./hathor
COPY README.md ./
RUN uv sync --frozen
RUN uv build --sdist --wheel
RUN uv pip install dist/hathor-*.whl

# finally: use production .venv from before
# lean and mean: this image should be about ~50MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON-slim-$DEBIAN
ARG PYTHON
RUN apt-get -qy update
#RUN apt-get -qy install libssl1.1 graphviz librocksdb6.11
RUN apt-get -qy install libssl3 graphviz librocksdb7.8
COPY --from=stage-0 /app/.venv/lib/python${PYTHON}/site-packages/ /usr/local/lib/python${PYTHON}/site-packages/
# XXX: copy optional BUILD_VERSION file using ...VERSIO[N] instead of ...VERSION* to ensure only one file will be copied
# XXX: also copying the README.md because we need at least one existing file
COPY README.md BUILD_VERSIO[N] /
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
