#!/usr/bin/env python3
"""
TCP proxy server developed in Python.
"""

import sys
import argparse
import textwrap
import ipaddress
import re
import threading
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR


INET4Addr = tuple[str, int]

RECV_TIMEOUT = 2
RECV_BUFFER_DIM = 4096
LISTEN_CONNECTIONS = 5
PRINTABLE_CHARS = (
    '................................ !"#$%&\'()*+,-./0123456789:;<=>?'
    '@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~.'
    '.................................¡¢£¤¥¦§¨©ª«¬.®¯°±²³´µ¶·¸¹º»¼½¾¿'
    'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ'
)

"""
PRINTABLE_CHARS holds the all printable bytes from 0 to 255.
The following code produces this string
    PRINTABLE_CHARS = ''.join(
        chr(i) if len(repr(chr(i))) == 3 else '.' for i in range(256)
    )
"""

def main():
    cmd_desc = "TCP proxy server implemented in Python"
    usage_examples = textwrap.dedent("""\
    Examples: 
        # Forward from (localhost, 8787) to (10.13.178.44, 80)
        proxy.py localhost  8787  10.13.178.44  80
                                    
        # Forward classical FTP, receive first (might need sudo)
        [sudo] proxy.py 192.168.64.1  21  10.13.178.44  21  -r
    """)
    parser = argparse.ArgumentParser(
        description = cmd_desc,
        epilog = usage_examples,
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'proxy_server_host',
        type = ensure_valid_host_or_ip,
        help = 'Listen on this host name or IPv4 address',
    )
    parser.add_argument(
        'proxy_server_port',
        type = positive_int,
        help = 'Listen on this port',
    )
    parser.add_argument(
        'remote_host',
        type = ensure_valid_host_or_ip,
        help = 'Forward to this host name or IPv4 address',
    )
    parser.add_argument(
        'remote_port',
        type = positive_int,
        help = 'Forward to this port',
    )
    parser.add_argument(
        '-r', '--receive-first',
        action = 'store_true',
        help = 'proxy will first wait for a buffer sent from the remote address',
    )
    parser.add_argument(
        '-t', '--timeout',
        type = positive_int,
        default = RECV_TIMEOUT,
        help = 'timeout between mediating calls in seconds',
    )

    args = parser.parse_args()
    proxy_server(
        (args.proxy_server_host, args.proxy_server_port),
        (args.remote_host, args.remote_port),
        args.receive_first,
        args.timeout,
    )
#:

def proxy_server(
        proxy_server_addr: INET4Addr,
        remote_addr: INET4Addr,
        receive_first = False,
        timeout = RECV_TIMEOUT,
):
    print_status(f"[*] STARTING proxy server at {proxy_server_addr[0]}:{proxy_server_addr[1]}")
    print_status(f"[*] FORWARDING connections to {remote_addr[0]}:{remote_addr[1]}")
    print_status(f"[*] RECEIVING FIRST? {receive_first}")
    print_status(f"[*] TIMEOUT set to {timeout}s")
    exit_code = 0
    try:
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server_socket.bind(proxy_server_addr)
            print_status(f"[*] Bound server socket to {proxy_server_addr[0]}:{proxy_server_addr[1]}")
            server_socket.listen(LISTEN_CONNECTIONS)

            while True:
                print_status("[*] Waiting for connections ...")
                client_socket, client_addr = server_socket.accept()
                print_status(f"[*] Connection from {client_addr[0]}:{client_addr[1]}")

                proxy_handler(client_socket, remote_addr, receive_first, timeout)

                # handler_thread = threading.Thread(
                #     target = proxy_handler,
                #     args = (client_socket, remote_addr, receive_first, timeout),
                # )
                # handler_thread.start()

    except KeyboardInterrupt:
        print_status("CTRL+C pressed...")
    except Exception as ex:
        print_status(f"[!] Error {type(ex).__name__}: {ex}")
        exit_code = 10
    finally:
        print_status("Exiting...")
        sys.exit(exit_code)
#:

def proxy_handler(
        client_socket: socket,
        remote_addr: INET4Addr,
        receive_first = False,
        timeout = RECV_TIMEOUT
):
    exit_code = 0
    try:
        with client_socket, socket(AF_INET, SOCK_STREAM) as remote_socket:
            remote_socket.connect(remote_addr)

            if receive_first:
                if remote_buffer := receive_from(remote_socket, timeout):
                    print_status(f"[<=] Received {len(remote_buffer)} bytes from remote host")
                    print_hexdump(remote_buffer)

                    print_status(f"[<=] Sending {len(remote_buffer)} bytes to client ...")
                    client_socket.send(remote_buffer)
                    print_status(f"     ... {len(remote_buffer)} bytes were sent!")

            while True:
                if client_buffer := receive_from(client_socket, timeout):
                    print_status(f"[=>] Received {len(client_buffer)} bytes from client ")
                    print_hexdump(client_buffer)

                    print_status(f"[=>] Sending {len(client_buffer)} bytes to remote host ...")
                    remote_socket.send(client_buffer)
                    print_status(f"     ... {len(client_buffer)} bytes were sent!")

                if remote_buffer := receive_from(remote_socket, timeout):
                    print_status(f"[<=] Received {len(remote_buffer)} bytes from remote host")
                    print_hexdump(remote_buffer)

                    print_status(f"[<=] Sending {len(remote_buffer)} bytes to client ...")
                    client_socket.send(remote_buffer)
                    print_status(f"     ... {len(remote_buffer)} bytes were sent!")

                if not (client_buffer or remote_buffer):  # if len(client_buffer) == 0 and len(remote_buffer) == 0:
                    print("[*] End of data transfer")
                    break

    except ConnectionResetError:
        print_status("[*] Connection closed by peer...")
    except ConnectionRefusedError as ex:
        print_status(f"[!] Connection refused when connecting to remote address: {ex}")
        exit_code = 3
    except ConnectionAbortedError as ex:
        print_status(f"[!] Connection aborted: {ex}")
        exit_code = 4
    except Exception as ex:
        print_status(f"[!] Error {type(ex).__name__}: {ex}")
        exit_code = 10
    finally:
        exit_markup = '*' if exit_code == 0 else '!'
        print_status(f"[{exit_markup}] Exiting from handler")
#:

def receive_from(sock: socket, timeout = RECV_TIMEOUT) -> bytes:
    buffer = bytearray()
    sock.settimeout(timeout)
    try:
        while block := sock.recv(RECV_BUFFER_DIM):
            buffer += block
            if len(block) < RECV_BUFFER_DIM:
                break
    except TimeoutError:
        print_status("[*] Timeout, moving on!")
    return bytes(buffer)
#:

################################################################################
##
##      UTILITIES
##
################################################################################

def print_hexdump(*hexdump_args, file = sys.stdout, **hexdump_kargs):
    for line in hexdump(*hexdump_args, **hexdump_kargs):
        print(line, file = file)
#:

def hexdump(data: str | bytes, line_length = 16, charset = 'UTF-8'):
    """
    This functions breaks `data` in lines of `line_length` bytes and
    yields hexdump lines containing three fields: 
    1. hexadecimal "address" in multiples of 16 bytes 
    2. hexadecimal representation for the line, with each byte 
    represented as a pair of hexadecimal digits
    3.textual representation for the line, a character is shown for
    each byte that corresponds to an actual character in the current
    charset, or a dot if the byte can't be displayed.

    Example:
    >>> for line in hexdump(b'\x00!$$type:*xmg$$G\xad\xd9Ol\xb7\xc1E<\x89\x98\xa5\xb6x\xb9\xddL'):
    ...     print(line)
    0000 | 00 21 24 24 74 79 70 65 3A 2A 78 6D 67 24 24 47  .!$$type:*xmg$$G
    0010 | AD D9 4F 6C B7 C1 45 3C 89 98 A5 B6 78 B9 DD 4C  .ÙOl·ÁE<..¥¶x¹ÝL
    """
    if isinstance(data, str):
        data = data.encode(charset)
    elif isinstance(data, bytearray):
        data = bytes(data)
    # As of 06/25 VSCode can't narrow the type down to bytes
    assert isinstance(data, bytes), 'Data should be bytes'

    for i in range(0, len(data), line_length):
        line = data[i:i + line_length]
        printable = ''.join(PRINTABLE_CHARS[b] for b in line)
        hexa = ' '.join(f'{b:02X}' for b in line)
        hexa_width = line_length * 3
        yield f'{i:04X} | {hexa:<{hexa_width}} {printable}'
#:

def ensure_valid_host_or_ip(host_or_ip: str) -> str:
    try: 
        ipaddress.ip_address(host_or_ip)
    except ValueError:
        if not is_valid_hostname(host_or_ip):
            raise argparse.ArgumentTypeError(f'Not a valid hostname nor IPv4 address "{host_or_ip}"')
    return host_or_ip
#:

def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC 
        referenced there)
        """
        if not 0 < len(hostname) <= 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()


def positive_int(val) -> int:
    val = int(val)
    if val < 0:
        raise argparse.ArgumentTypeError('Not a positive int')
        # raise TypeError('Not a positive int')
    return val
#:

def print_status(*args, **kargs):
    print(*args, **kargs, file=sys.stderr)
#:

if __name__ == '__main__':
    main()
