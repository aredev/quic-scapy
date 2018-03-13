from _curses import raw

from scapy import route
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, send, sr
from scapy.supersocket import L3RawSocket

from QUIC import QUICHeader


def send_chlo():
    chlo = QUICHeader()
    # bind_layers(UDP, QUICHeader)

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst="192.168.43.228") / UDP(dport=6121) / chlo
    # print(p.show())
    response = sr(p)
    print(response[0].payload())

send_chlo()


def create_n_bytes_from_string(long_byte, name):
    n = 2
    list_of_two_chars = [long_byte[i:i+n] for i in range(0, len(long_byte), n)]
    for idx, byte in enumerate(list_of_two_chars):
        print("XByteField(\"" + name + str(idx) + "\", 0x" + str(byte) + "), ")


# create_n_bytes_from_string("00000000000000000000000000000000000000", "end_padding")