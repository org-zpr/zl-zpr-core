#!/usr/bin/env python3
"""A UDP/53 echo service and its client, for the Zode netns tests.

    udp_echo.py serve
        Answer every datagram on [::]:53 with "reply:" and the datagram.

    udp_echo.py query DST ROUNDS
        ROUNDS rounds; each sends two queries at once to DST:53 from two
        fresh sockets, as a DNS resolver sends its A and AAAA queries, and
        waits up to 3 s for both replies. Each round is a new pair of flows,
        so each needs a visa match. Exits 0 only if every query is answered.
"""

import select
import socket
import sys
import time

PORT = 53
WAIT_SECONDS = 3


def serve():
    """Echo every datagram back to its sender, forever."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", PORT))
    while True:
        data, addr = sock.recvfrom(2048)
        sock.sendto(b"reply:" + data, addr)


def query(dst, rounds):
    """Run the query rounds against dst; return how many replies came."""
    answered = 0
    for round_no in range(rounds):
        socks = [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) for _ in range(2)]
        for i, sock in enumerate(socks):
            sock.sendto(b"q%d-%d" % (round_no, i), (dst, PORT))
        got = set()
        deadline = time.time() + WAIT_SECONDS
        while len(got) < len(socks) and time.time() < deadline:
            ready, _, _ = select.select(socks, [], [], max(0, deadline - time.time()))
            for sock in ready:
                sock.recv(2048)
                got.add(sock)
        answered += len(got)
        for sock in socks:
            sock.close()
    return answered


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        dst, rounds = sys.argv[2], int(sys.argv[3])
        answered = query(dst, rounds)
        print("replies %d of %d" % (answered, 2 * rounds))
        sys.exit(0 if answered == 2 * rounds else 1)
