Hathor Network
==============

Connect to Hathor testnet
------

Run:

    python main.py --listen tcp:8000:interface=0.0.0.0 --testnet

You can include `--status 8001` to run a status web server in port 8001. To access your
status server, open the brower in http://localhost:80001/.

By default, it will listen in all interfaces (0.0.0.0).



Run a simple test in one computer
------

First run a server which listens for new connections:

    python main.py --listen tcp:8000

Then, run a client which connects to the server. You may run as many clients as you want.

    python main.py --bootstrap tcp:127.0.0.1:8000



Generate a peer id
------

To generate a random peer id, run:

    python gen_peer_id.py > mypeer.json

Then, you can use this id in any server or client through the `--peer` parameter. For instance:

    python main.py --listen tcp:8000 --peer mypeer.json



Cheat Sheets
------

Run flake8:

    flake8 hathor/ tests/ *.py

Run tests with coverage:

	nosetests --with-coverage --cover-package=hathor --cover-html
