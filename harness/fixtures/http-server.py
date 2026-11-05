#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
"""The lab's HTTP target: `python3 -m http.server` without the reverse lookup.

The standard server names itself with `socket.getfqdn(<bind address>)`, a reverse DNS lookup
through the host's resolvers. From a lab namespace whose default route leads to the router and
no further, that lookup waits out the resolver's timeouts before the first byte is served. This
server binds and serves at once, logging each request exactly as the standard one does
(`<client> - - [<date>] "GET / HTTP/1.0" 200 -`); the ready line is `Serving HTTP on <bind>
port <port>`."""

import argparse
import http.server
import socket
import socketserver
from functools import partial


class Server(http.server.ThreadingHTTPServer):
    """The standard server, named after its address instead of a reverse lookup."""

    allow_reuse_address = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="the address to listen on, IPv4 or IPv6")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--directory", required=True, help="the directory served")
    args = parser.parse_args()
    family, _, _, _, address = socket.getaddrinfo(
        args.bind,
        args.port,
        type=socket.SOCK_STREAM,
        flags=socket.AI_PASSIVE | socket.AI_NUMERICHOST,
    )[0]
    Server.address_family = family
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=args.directory)
    with Server(address, handler) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f"[{host}]" if ":" in host else host
        print(f"Serving HTTP on {host} port {port} (http://{url_host}:{port}/) ...", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
