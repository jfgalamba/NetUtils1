"""
Exemplo de um cliente TCP.
"""

from socket import socket, AF_INET, SOCK_STREAM

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888                # porto para acesso HTTP

# SERVER_HOST = "www.google.com"
# SERVER_PORT = 80                # porto para acesso HTTP


def main():
    # Criar objecto socket
    # AF_INET -> Internet, IPv4 |  SOCK_STREAM -> TCP (orientado ao byte)
    client_socket = socket(AF_INET, SOCK_STREAM)

    # Ligar ao servidor
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Enviar pedido/método GET
    request = b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'
    """
    O request corresponde a um "pacote" HTTP. Se fizermos um print do request 
    obtemos:
        GET / HTTP/1.1 
        Host: google.com
    """
    client_socket.send(request)

    # Aguarda por uma resposta (e reserva um buffer com 8192 bytes para essa resposta)
    response = client_socket.recv(8192)
    print(response.decode())
    client_socket.close()
#:

if __name__ == '__main__':
    main()