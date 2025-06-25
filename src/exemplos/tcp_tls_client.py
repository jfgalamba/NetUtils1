"""
Exemplo de um cliente que utiliza TLS/SSL.
Utiliza o módulo ssl da biblioteca padrão do Python:

"This module provides access to Transport Layer Security (often known as
“Secure Sockets Layer”) encryption and peer authentication facilities
for network sockets, both client-side and server-side. This module uses
the OpenSSL library. It is available on all modern Unix systems,
Windows, macOS, and probably additional platforms, as long as OpenSSL is
installed on that platform."

"This module provides a class, ssl.SSLSocket, which is derived from
the socket.socket type, and provides a socket-like wrapper that also
encrypts and decrypts the data going over the socket with SSL. It
supports additional methods such as getpeercert(), which retrieves the
certificate of the other side of the connection, cipher(), which
retrieves the cipher being used for the secure connection or
get_verified_chain(), get_unverified_chain() which retrieves
certificate chain. For more sophisticated applications, the
ssl.SSLContext class helps manage settings and certificates, which can
then be inherited by SSL sockets created through the
SSLContext.wrap_socket() method."
"""

import socket
import ssl

# SERVER_HOST = "www.python.org"
SERVER_HOST = "www.google.com"


def main():
    context = ssl.create_default_context()

    # Utiliza função create_connection 
    # https://docs.python.org/3/library/socket.html#socket.create_connection
    with socket.create_connection((SERVER_HOST, 443)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname=SERVER_HOST) as ssock:
            print(ssock.version())

            # Enviar pedido/método GET
            request = f'GET / HTTP/1.1\r\nHost: {SERVER_HOST}\r\n\r\n'.encode()
            ssock.send(request)

            # Aguarda por uma resposta (e reserva um buffer com 8192 bytes para
            # essa resposta)
            while response := ssock.recv(8192):
                print(response.decode(encoding='ISO-8859-1'))
#:

if __name__ == '__main__':
    main()
