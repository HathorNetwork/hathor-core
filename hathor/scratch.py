import os
import select
import socket
import time

def run_client(client_sock, addr):
    print("New connection", client_sock, addr)
    # time.sleep(5)
    client_sock.setblocking(True)
    data = client_sock.recv(1024)
    print(f"Received data: {repr(data)}")
    client_sock.close()
    os._exit(-1)


def main():
    # Path to the UDS socket file
    socket_file = '/tmp/uds_socket'

    # Remove old socket file if it exists
    if os.path.exists(socket_file):
        os.remove(socket_file)

    # Create a UDS socket
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(socket_file)
    server_sock.listen(5)
    server_sock.setblocking(False)

    # List of sockets to monitor for incoming data
    sockets_to_monitor = [server_sock]
    print('running')

    while True:
        print('loop')
        readable, writable, exceptional = select.select(sockets_to_monitor, [], [])
        assert len(readable) == 1
        sock = readable[0]
        print('sock', sock)
        # Accept new connection
        client_sock, addr = server_sock.accept()

        pid = os.fork()
        if pid == 0:
            server_sock.close()
            run_client(client_sock, addr)
        else:
            client_sock.close()

try:
    main()
except KeyboardInterrupt:
    pass
