# Hathor Network

[![Mainnet](https://img.shields.io/badge/mainnet-live-success)](https://explorer.hathor.network/)
[![Version](https://img.shields.io/github/v/release/HathorNetwork/hathor-core)](https://github.com/HathorNetwork/hathor-core/releases/latest)
[![Testing](https://img.shields.io/github/workflow/status/HathorNetwork/hathor-core/tests?label=tests&logo=github)](https://github.com/HathorNetwork/hathor-core/actions?query=workflow%3Atests+branch%3Amaster)
[![Docker Hub](https://img.shields.io/docker/cloud/build/hathornetwork/hathor-core?logo=docker)](https://hub.docker.com/repository/docker/hathornetwork/hathor-core)
[![Codecov](https://img.shields.io/codecov/c/github/HathorNetwork/hathor-core?logo=codecov)](https://codecov.io/gh/hathornetwork/hathor-core)
[![Discord](https://img.shields.io/discord/566500848570466316?logo=discord)](https://discord.com/invite/35mFEhk)
[![License](https://img.shields.io/github/license/HathorNetwork/hathor-core)](./LICENSE.txt)

## Running a full-node

### Using Docker

The easiest way to run a full-node is to use our Docker image. If you don't have Docker installed, check out [this
link](https://docs.docker.com/install/). So, just run:

```
docker run -ti -p 8080:8080 -p 8081:8081 hathornetwork/hathor-core run_node --cache --status 8080 --stratum 8081
```

The `--status 8080` will run our HTTP API on port 8080, while the `--stratum 8081` will run a stratum server on port
8081. You can check your full-node status accessing `http://localhost:8000/v1a/status/`. Use `--help` for more
parameters.

For more information about our HTTP API, check out our [API Documentation](https://docs.hathor.network/).


## From source-code

First, you need to have Python 3.6 installed. If you don't, we recommend you to install using `pyenv` (check this
[link](https://github.com/pyenv/pyenv#installation)).

### System dependencies

- on Ubuntu 20.04 (without using `pyenv`):

  ```
  sudo add-apt-repository ppa:deadsnakes/ppa
  sudo apt update
  sudo apt install python3.6 python3.6-dev python3.6-pip build-essential
  pip install -U pipenv
  ```
- on macOS:

  ```
  brew install pyenv
  pyenv install 3.6.10
  pyenv local 3.6.10
  pip install -U pipenv
  ```
- on Windows 10 (using [winget](https://github.com/microsoft/winget-cli)):

  ```
  winget install python-3.6
  pip install -U pipenv
  ```

### Clone the project and install pipenv dependencies

```
git clone git@github.com:HathorNetwork/hathor-core.git && cd hathor-core
pipenv sync -d
```

Generate protobuf modules:

```
pipenv run make protos
```

### Running the full-node

```
pipenv run ./hathor-cli run_node --status 8080
```

## Additional considerations

### Data persistence

By default, the full node uses a memory storage. It means that, if the node is restarted, it will have to sync all
blocks and transactions again. You can use a persistent storaged by passing a directory where data will be stored by
using parameter `--data`.

```
pipenv run ./hathor-cli run_node --status 8080 --data /data
```

#### With Docker

When running the full node with Docker and using a persistent storage, it's best to bind a Docker volume to a host
directory. This way, the container may be restarted or even destroyed and the data will be safe.

To bind the volume, use parameter `-v host-dir:conatiner-dir:options` ([Docker
documentarion](https://docs.docker.com/engine/reference/run/#volume-shared-filesystems)).

```
docker run -v ~/hathor-data:/data:consistent ... run_node ... --data /data
```

### Using a peer-id

It's optional, but generally recommended, first generate a peer-id file:

```
pipenv run ./hathor-cli gen_peer_id > peer_id.json
```

Then, you can use this id in any server or client through the `--peer` parameter. For instance:

```
hathor-cli run_node --listen tcp:8000 --peer peer_id.json
```

## Common development commands

Assuming virtualenv is active, otherwise prefix `make` commands with `pipenv run`.

Check if code seems alright:

```
make check
```

Test and coverage:

```
make tests
```

Generate Sphinx docs:

```
cd docs
make html
make latexpdf
```

The output will be written to `docs/_build/html/`.
