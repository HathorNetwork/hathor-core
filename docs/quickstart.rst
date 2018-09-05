
Quick start
===========

Connect to Hathor testnet
-------------------------

Run:

.. code-block:: shell

    python main.py --listen tcp:8000:interface=0.0.0.0 --testnet

You can include `--status 8001` to run a status web server in port 8001. To access your
status server, open the brower in http://localhost:80001/.

By default, it will listen in all interfaces (0.0.0.0).



Run a simple test in one computer
---------------------------------

First run a server which listens for new connections:

.. code-block:: shell

    python main.py --listen tcp:8000

Then, run a client which connects to the server. You may run as many clients as you want.

.. code-block:: shell

    python main.py --bootstrap tcp:127.0.0.1:8000

To run multiple nodes in one server:

.. code-block:: shell

	python main.py --hostname localhost --listen tcp:8000 --status 8080 --peer peer0.json --data ./peer0/data/
	python main.py --hostname localhost --listen tcp:8001 --status 8081 --peer peer1.json --data ./peer1/data/ --bootstrap tcp:127.0.0.1:8000


Run a simple miner
------------------

.. code-block:: shell

    python mining.py http://localhost:8080/mining --sleep 0.0001


Generate a peer id
------------------

To generate a random peer id, run:

.. code-block:: shell

    python gen_peer_id.py > mypeer.json

Then, you can use this id in any server or client through the `--peer` parameter. For instance:

.. code-block:: shell

    python main.py --listen tcp:8000 --peer mypeer.json



Cheat Sheets
------------

Run flake8:

.. code-block:: shell

    flake8 hathor/ tests/ *.py

Run tests with coverage:

.. code-block:: shell

	nosetests --with-coverage --cover-package=hathor --cover-html



How to create a full-node in Ubuntu 16.04
-----------------------------------------

First, install all packages:

.. code-block:: shell

    sudo apt update
    sudo apt install --assume-yes python3 python3-dev python3-setuptools build-essential
    sudo apt install --assume-yes supervisor  # optional
    sudo easy_install3 pip
    pip3 install virtualenv --user

Then, install `hathor-python`:

.. code-block:: shell

    git clone git@gitlab.com:HathorNetwork/hathor-python.git
    cd hathor-python/
    virtualenv --python=python3 venv
    source ./venv/bin/activate
    pip install -r requirements.txt

Then, generate your `peer_id.json`:

.. code-block:: shell

    python gen_peer_id.py >peer_id.json

Finally, you can run your node.



Daemonizing with Supervisor
---------------------------

Create a `run_hathord` with execution permission:

.. code-block:: shell

    #!/bin/bash
    source ./venv/bin/activate
    exec python main.py --hostname <YOUR_HOSTNAME_OR_PUBLIC_IP_ADDRESS> --listen tcp:40403 --status 8001 --testnet --peer peer_id.json

There follows a configuration template to Supervisor:

.. code-block:: ini

    [program:hathord]
    command=/path/to/hathor-python/run_hathord
    user=ubuntu
    directory=/path/to/hathor-python/
    stdout_logfile=/path/to/logs/hathord.log
    stderr_logfile=/path/to/logs/hathord.err

Recommended aliases to control `hathord`:

.. code-block:: shell

    alias stop-hathord='sudo supervisorctl stop hathord'
    alias start-hathord='sudo supervisorctl start hathord'
    alias status-hathord='sudo supervisorctl status hathord'
    alias restart-hathord='sudo supervisorctl restart hathord'
    alias p2p-hathord='curl http://localhost:8001/'
