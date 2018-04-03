from _curses import raw

import socket
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Raw, bind_layers
from scapy.sendrecv import sr1, send, sr, sniff
from scapy.supersocket import L3RawSocket
from scapy.utils import hexdump

from ACKPacket import ACKPacket
from FullCHLOPacket import FullCHLOPacket
from QUIC import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from VersionNegotiation import VersionNegotiationPacket
from VersionProposalPacket import VersionProposalPacket
from crypto.fnv128a import FNV128A
from crypto.hkdf import Hkdf
from util.SessionInstance import SessionInstance

destination_ip = "192.168.1.70"
server_config_id = ""


def send_chlo():
    chlo = QUICHeader()
    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)

    for key, value in a.fields.items():
        print("Key:{}==Value:{}".format(key, value))

    server_config_id_key = "﻿Server_Config_ID_Value"
    server_config_id = a.fields[server_config_id_key]
    print(server_config_id)
    # print(a.fields.get_field('﻿Server_Config_ID_Value')) # Retrieving a value from a packet
    session = SessionInstance.get_instance()
    # session.server_config_id = server_config_id
    # print(a)

send_chlo()


def send_first_ack():
    chlo = ACKPacket()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


send_first_ack()


def send_second_ack():
    chlo = SecondACKPacket()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


send_second_ack()

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
    chlo = FullCHLOPacket()

    public_flags = chlo.fields['Public Flags']
    cid = chlo.fields['CID']
    version = chlo.fields['Version']
    packet_number = chlo.fields['Packet Number']
    # print(chlo.get_field('Public Flags').default)
    FNV128A().generate_hash(public_flags, cid, version, packet_number, bytes())

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)
    # print(a.show())
    # server_nonce = a.fields['Server_Nonce_Value']



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

# create_n_bytes_from_string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "Padding")

