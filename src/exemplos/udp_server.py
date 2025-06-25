"""
Exemplo de um servidor UDP.
"""

from socket import socket, AF_INET, SOCK_DGRAM
import threading


BUFFER_DIM = 8192
IP = '0.0.0.0'
PORT = 8080


def main():
    with socket(AF_INET, SOCK_DGRAM) as serv_socket:
        serv_socket.bind((IP, PORT))
        print(f"[+] Waiting for requests on IP {IP} and PORT {PORT}")

        while True:
            request, client_addr = serv_socket.recvfrom(BUFFER_DIM)
            print(f"[+] Client addr => {client_addr}")
            print(f"[+] Client request => {request.decode()}")
            client_thread = threading.Thread(target=handle_client, args=(client_addr, request,))
            client_thread.start()
#:

def handle_client(client_addr: tuple[str, int], request: bytes):
    with socket(AF_INET, SOCK_DGRAM) as client_socket:
        client_socket.sendto(b'OK', client_addr)
#:

if __name__ == '__main__':
    main()

