#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
"""The lab's SNTP server (SPEC §11): answers every mode 3 request with mode 4, the given stratum,
reference id LOCL and this host's clock shifted by --offset seconds, so scenarios can dial in a
server that is two hours ahead, one stuck in 2013, or one that is simply right. Each request is
logged as `query from <addr>:<port>`; the ready line is `sntp-server listening on <bind>:<port>`.
With --unsync it answers LI 3, stratum 16 like a server that has lost its own source."""

import argparse
import socket
import struct
import sys
import time

UNIX_OFFSET = 2_208_988_800  # 1900-01-01 to 1970-01-01


def ntp_timestamp(unix_seconds: float) -> int:
    seconds, fraction = divmod(unix_seconds + UNIX_OFFSET, 1)
    return (int(seconds) % (1 << 32)) << 32 | int(fraction * (1 << 32))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=123)
    parser.add_argument("--offset", type=float, default=0.0, help="seconds added to this host's clock")
    parser.add_argument("--stratum", type=int, default=2)
    parser.add_argument("--unsync", action="store_true", help="answer as an unsynchronised server")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"sntp-server listening on {args.bind}:{args.port}", flush=True)
    while True:
        data, peer = sock.recvfrom(512)
        if len(data) < 48:
            continue
        first = data[0]
        version = (first >> 3) & 0x7
        mode = first & 0x7
        if mode != 3 or version not in (3, 4):
            continue
        print(f"query from {peer[0]}:{peer[1]}", flush=True)
        now = time.time() + args.offset
        if args.unsync:
            leap, stratum, refid = 3, 16, b"\0\0\0\0"
        else:
            leap, stratum, refid = 0, args.stratum, b"LOCL"
        transmit = ntp_timestamp(now)
        reply = struct.pack(
            "!BBbbIi4sQQQQ",
            (leap << 6) | (version << 3) | 4,
            stratum,
            data[2],  # the client's poll
            -20,  # precision: about a microsecond
            0x0000_0400,  # root delay: 1/64 s
            0x0000_0200,  # root dispersion: 1/128 s
            refid,
            ntp_timestamp(now - 8),  # reference: "synced" eight seconds ago
            struct.unpack("!Q", data[40:48])[0],  # originate: the client's transmit
            transmit,  # receive
            transmit,  # transmit
        )
        sock.sendto(reply, peer)


if __name__ == "__main__":
    sys.exit(main())
