from _curses import raw

import socket
from scapy import route
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Raw, bind_layers
from scapy.sendrecv import sr1, send, sr, sniff
from scapy.supersocket import L3RawSocket
from scapy.utils import hexdump

from QUIC import QUICHeader
from RejectionPacket import RejectionPacket
from VersionNegotiation import VersionNegotiationPacket
from VersionProposalPacket import VersionProposalPacket
from crypto.hkdf import Hkdf

destination_ip = "192.168.43.228"

def send_chlo():
    chlo = QUICHeader()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)
    print(a.show())


send_chlo()


def send_version_proposal():
    version_proposal = VersionProposalPacket()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / version_proposal
    # print(p.show())
    ans, _ = sr(p)
    a = RejectionPacket(ans[0][1][1].payload.load)
    print(a.show())


def send_full_chlo():
    pass



# send_full_chlo()


def send_encrypted_request():
    pass


# send_encrypted_request()
# send_version_proposal()

def create_n_bytes_from_string(long_byte, name):
    n = 2
    list_of_two_chars = [long_byte[i:i+n] for i in range(0, len(long_byte), n)]
    for idx, byte in enumerate(list_of_two_chars):
        print("XByteField(\"" + name + str(idx) + "\", 0x" + str(byte) + "), ")

# create_n_bytes_from_string("2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d", "padding")


