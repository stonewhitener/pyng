#!/usr/bin/env python3
import argparse
import selectors
import socket
import struct

from ethernet import *


def main(interface):
    # Create a layer 2 raw socket that receive any Ethernet frames (= ETH_P_ALL)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as server_socket:
        # Bind the interface
        server_socket.bind((interface, 0))
        with selectors.DefaultSelector() as selector:
            # Resister the socket for selection, monitoring it for I/O events
            selector.register(server_socket.fileno(), selectors.EVENT_READ)
            while True:
                # Wait until the socket become readable
                ready = selector.select()
                if ready:
                    # Receive a frame
                    frame = server_socket.recv(ETH_FRAME_LEN)
                    # Extract a header
                    header = frame[:ETH_HLEN]
                    # Unpack an Ethernet header in network byte order
                    dst, src, proto = struct.unpack('!6s6sH', header)
                    # Extract a payload
                    payload = frame[ETH_HLEN:]
                    print(f'dst: {bytes_to_eui48(dst)}, '
                          f'src: {bytes_to_eui48(src)}, '
                          f'type: {hex(proto)}, '
                          f'payload: {payload[:4]}...')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pyng server')
    parser.add_argument('interface', type=str, help='interface name')
    args = parser.parse_args()
    main(args.interface)
