"""
Exemplo de um servidor TCP.
"""

from socket import socket, AF_INET, SOCK_STREAM
import threading

BUFFER_DIM = 8192
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 8888


def main():
    with socket(AF_INET, SOCK_STREAM) as serv_socket:
        serv_socket.bind((LISTEN_IP, LISTEN_PORT))
        serv_socket.listen()

        print(f"[+] Listening on IP {LISTEN_IP} and PORT {LISTEN_PORT}")

        while True:
            client_socket, client_addr = serv_socket.accept()
            print(f"[+] Accepted connection from ({client_addr[0]}, {client_addr[1]})")

            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            client_thread.start()

def handle_client(client_socket: socket, client_addr: tuple[str, int]):
    with client_socket:
        request = client_socket.recv(BUFFER_DIM)
        print(f"[+] Client request => {request.decode()}")
        client_socket.send(f"OK {client_addr[0]} {client_addr[1]}".encode()) 

if __name__ == '__main__':
    main()
