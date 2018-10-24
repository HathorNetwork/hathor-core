#!/bin/bash

service nginx start

# python3 gen_peer_id.py >peer_id.json

WORDS='index talent enact review cherry lunch vacuum chef alone general rhythm banana helmet dash sudden tobacco income search magic bar crater lens caution coin'

su hathor -c "exec hathor-cli run_node --status 8001 --words \"${WORDS}\" $@"
