import binascii
import fcntl
import re
import socket
import struct


__all__ = ['ETH_ALEN', 'ETH_TLEN', 'ETH_HLEN', 'ETH_ZLEN', 'ETH_DATA_LEN', 'ETH_FRAME_LEN',
           'ETH_P_ALL', 'ETH_P_IP', 'ETH_P_ARP', 'ETH_P_802_EX1', 'ETH_P_802_EX2',
           'bytes_to_eui48', 'eui48_to_bytes', 'get_hardware_address']


# Definitions of the socket-level I/O control calls.
# Source: https://github.com/torvalds/linux/blob/master/include/uapi/linux/sockios.h
_SIOCGIFHWADDR = 0x8927      # Get hardware address


# Global definitions for the Ethernet IEEE 802.3 interface.
# Source: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
ETH_ALEN = 6                # Octets in one ethernet addr
ETH_TLEN = 2                # Octets in ethernet type field
ETH_HLEN = 14               # Total octets in header.
ETH_ZLEN = 60               # Min. octets in frame sans FCS
ETH_DATA_LEN = 1500         # Max. octets in payload
ETH_FRAME_LEN = 1514        # Max. octets in frame sans FCS

ETH_P_ALL = 0x0003          # Every packet (be careful!!!)
ETH_P_IP = 0x0800           # Internet Protocol packet
ETH_P_ARP = 0x0806          # Address Resolution packet
ETH_P_802_EX1 = 0x88B5      # Local Experimental Ethertype 1
ETH_P_802_EX2 = 0x88B6      # Local Experimental Ethertype 2


def bytes_to_eui48(b: bytes, sep=':'):
    """Convert bytes to MAC address (EUI-48) string."""
    if len(b) != ETH_ALEN:
        raise ValueError()
    if sep != ':' and sep != '-':
        raise ValueError()
    return sep.join('%02x' % octet for octet in b)


def eui48_to_bytes(s: str):
    """Convert MAC address (EUI-48) string to bytes."""
    if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', s):
        sep = ':'
    elif re.match(r'^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$', s):
        sep = '-'
    else:
        raise ValueError('invalid format')
    return binascii.unhexlify(''.join(s.split(sep)))


def get_hardware_address(interface):
    """Get hardware address of specific interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # Invoke ioctl for a socket descriptor to obtain a hardware address
        info = fcntl.ioctl(s.fileno(), _SIOCGIFHWADDR, struct.pack('256s', interface[:15].encode()))
        return info[18:24]
