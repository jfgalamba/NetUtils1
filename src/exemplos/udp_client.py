"""
Exemplo de um cliente UPP.
"""

from socket import socket, AF_INET, SOCK_DGRAM

def main():
    target_host = "127.0.0.1"
    target_port = 8080        # porto do servidor UDP

    # Criar objecto socket
    # AF_INET -> Internet, IPv4 |  SOCK_DGRAM -> UDP (envia grupos de bytes)
    client_socket = socket(AF_INET, SOCK_DGRAM)

    # Enviar dados
    request = b'XYZ123'
    client_socket.sendto(request, (target_host, target_port))

    # Aguarda por uma resposta (e reserva um buffer com 8192 bytes para essa resposta)
    response, server_new_address = client_socket.recvfrom(8192)

    print(response.decode())
    client_socket.close()   # na verdade devemos abrir o socket com WITH e nesse
                            # caso o close é feito sempre que o bloco do WITH terminar
#:

if __name__ == '__main__':
    main()


