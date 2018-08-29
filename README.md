Hathor Network
==============

Run a simple test in one computer
------

First run a server which listens for new connections:

    python main.py --listen 0.0.0.0:8000

Then, run a client which connects to the server. You may run as many clients as you want.

    python main.py --bootstrap 127.0.0.1:8000



Generate a peer id
------

To generate a random peer id, run:

    python gen_peer_id.py > mypeer.json

Then, you can use this id in any server or client through the `--peer` parameter. For instance:

    python main.py --listen 0.0.0.0:8000 --peer mypeer.json



Cheat Sheets
------

Run flake8:

    flake8 hathor/ tests/ *.py

Run tests with coverage:

	nosetests --with-coverage --cover-package=hathor --cover-html
