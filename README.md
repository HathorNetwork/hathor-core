Hathor Network
==============

![tests](https://github.com/HathorNetwork/hathor-core/workflows/tests/badge.svg)
[![codecov](https://codecov.io/gh/hathornetwork/hathor-core/branch/dev/graph/badge.svg)](https://codecov.io/gh/hathornetwork/hathor-core)


Connect to Hathor testnet
------

Run (assuming virtualenv is active):

    hathor-cli run_node --listen tcp:8000:interface=0.0.0.0 --testnet

You can include `--status 8001` to run a status web server in port 8001. To access your
status server, open the brower in http://localhost:80001/.

By default, it will listen in all interfaces (0.0.0.0).

You have two wallet options: Hierarchical Deterministic Wallet (hd) and KeyPair simple wallet (keypair)

To decide which wallet you are going to use run with --wallet hd, for example. Default value is 'hd'

For hd wallet you can run --words and --passphrase to set the words and passphrase used to generate the initial seed


Build for pypy on MacOS with Brew
------

    pipenv sync -d


Run a simple test in one computer
------

Open a pipenv shell (or activate virtualenv):

    pipenv shell

First run a server which listens for new connections:

    hathor-cli run_node --listen tcp:8000

Then, run a client which connects to the server. You may run as many clients as you want.

    hathor-cli run_node --bootstrap tcp:127.0.0.1:8000

To run multiple nodes in one server:

    hathor-cli run_node --hostname localhost --listen tcp:8000 --status 8080 --peer peer0.json --data ./peer0/data/
    hathor-cli run_node --hostname localhost --listen tcp:8001 --status 8081 --peer peer1.json --data ./peer1/data/ --bootstrap tcp:127.0.0.1:8000


Run a simple miner
------

Assuming virutlenv:

    hathor-cli run_miner http://localhost:8080/mining --sleep 0.1

If you're running a miner, make sure you start the node with `--wallet /mywallet` parameter to specify the wallet directory. You can create a wallet using the `generate_wallet.py` script.

    python generate_wallet.py --count 50 --directory /mywallet


Generate a peer id
------

To generate a random peer id, run:

    hathor-cli gen_peer_id > peer_id.json

Then, you can use this id in any server or client through the `--peer` parameter. For instance:

    hathor-cli run_node --listen tcp:8000 --peer peer_id.json



Cheat Sheets
------

Assuming virtualenv is active, otherwise prefix `make` commands with `pipenv run`.

Check if code seems alright:

    make check

Test and coverage:

    make tests

Generate Sphinx docs:

    cd docs
    make html
    make latexpdf

The output will be written to `docs/_build/html/`.


How to create a full-node in Ubuntu 20.04
------

First, install all packages:

    sudo add-apt-repository ppa:deadsnakes/ppa
    sudo apt update
    sudo apt install python3.6 python3.6-dev python3.6-pip build-essential 
    sudo apt install supervisor  # optional    

Then, install `hathor-python`:

    git clone git@gitlab.com:HathorNetwork/hathor-python.git
    cd hathor-python/
    python3.6 -m pip install -U pipenv     
    python3.6 -m pipenv sync -d

Generate grpc/protobuf modules:

    python3.6 -m pipenv run make protos

Then, generate your `peer_id.json`:

    python3.6 -m pipenv run hathor-cli gen_peer_id > peer_id.json

Finally, you can run your node.


Daemonizing with Supervisor
------

Create a `run_hathord` with execution permission:

    #!/bin/bash
    exec python3.6 -m pipenv run hathor-cli run_node --hostname <YOUR_HOSTNAME_OR_PUBLIC_IP_ADDRESS> --listen tcp:40403 --status 8001 --testnet --peer peer_id.json

There follows a configuration template to Supervisor:

    [program:hathord]
    command=/path/to/hathor-python/run_hathord
    user=ubuntu
    directory=/path/to/hathor-python/
    stdout_logfile=/path/to/logs/hathord.log
    stderr_logfile=/path/to/logs/hathord.err

Recommended aliases to control `hathord`:

    alias stop-hathord='sudo supervisorctl stop hathord'
    alias start-hathord='sudo supervisorctl start hathord'
    alias status-hathord='sudo supervisorctl status hathord'
    alias restart-hathord='sudo supervisorctl restart hathord'
    alias p2p-hathord='curl http://localhost:8001/'


Notes for running on Windows 10
------

A few additional steps are required to run the code on Windows:

* If pip install has trouble installing `twisted`, install it from a wheel file appropriate for your environment.

    For example: download from a [repo of wheel files](https://www.lfd.uci.edu/~gohlke/pythonlibs/#twisted) and then:


    pip install Twisted-18.7.0-cp36-cp36m-win_amd64.whl

After this succeeds, you should be able to install the other requirements normally:

    pip install -r requirements.txt


* You may need to create a `\tmp` directory manually for the tests to run:

    mkdir c:\tmp

