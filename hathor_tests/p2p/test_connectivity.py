import time
import urllib
from contextlib import contextmanager
from typing import Generator

import requests

from hathor_tests.utils import run_server


@contextmanager
def _run_servers_context(count: int) -> Generator[list[tuple[str, str]], None, None]:
    """ Runs `count` number of `test.utils.run_server` that bootstrap in chain, yields a (endpoint, status_url) list.
    """
    if count > 80:
        raise ValueError('cannot start more than 80 processes at once')
    start_port = 8005
    endpoint_and_status_urls = []
    processes = []
    try:
        previous_endpoint: None | str = None
        for listen_port in range(start_port, start_port + count):
            status_port = listen_port + 80
            endpoint = f'tcp://127.0.0.1:{listen_port}'
            status_url = f'http://127.0.0.1:{status_port}'
            # XXX: it's important for run_server to be inside the try because if it fails it will still terminate the
            # ones that were previously started because they would have made it into the processes list
            processes.append(run_server(listen=listen_port, status=status_port, bootstrap=previous_endpoint))
            endpoint_and_status_urls.append((endpoint, status_url))
            previous_endpoint = endpoint
        yield endpoint_and_status_urls
    finally:
        for process in processes:
            # XXX: this assumes process.terminate() will not fail
            process.terminate()


def test_manager_connection_transitivity() -> None:
    """ Creates a chain of 4 peers that bootstrap to the previous one, they should all connect to each other.
    """
    with _run_servers_context(4) as endpoint_status_pairs:
        assert len(endpoint_status_pairs) == 4
        time.sleep(1)  # 1 sec should be more than enough for the peers to connect to themselves

        statuses = [
            requests.get(urllib.parse.urljoin(status_url, '/v1a/status/')).json()
            for _, status_url in endpoint_status_pairs
        ]

        all_peer_ids = set(status['server']['id'] for status in statuses)

        for status in statuses:
            peer_id = status['server']['id']
            all_other_peer_ids = all_peer_ids - {peer_id}
            connected_peer_ids = {i['id'] for i in status['connections']['connected_peers']}
            assert all_other_peer_ids == connected_peer_ids
