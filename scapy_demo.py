import binascii
import struct
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
from util.packet_to_hex import extract_from_packet
from util.string_to_ascii import string_to_ascii

destination_ip = "192.168.43.228"


def send_chlo():
    chlo = QUICHeader()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)

    for key, value in a.fields.items():
        if "Server_Config_ID" in key:
            print("Key {} has this value {}".format(key, value))
            SessionInstance.get_instance().server_config_id = value
        if "Source_Address_Token" in key:
            SessionInstance.get_instance().source_address_token = value

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
    print("Server config id according to session {}".format(SessionInstance.get_instance().server_config_id))

    chlo = FullCHLOPacket()
    chlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
    chlo.setfieldval('STK_Value', SessionInstance.get_instance().source_address_token)

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    print(associated_data)
    print(body)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    print("Computed message authentication hash {}".format(message_authentication_hash))

    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    # Set the MAH to the field

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)
    # print(a.show())
    # server_nonce = a.fields['Server_Nonce_Value']



send_full_chlo()


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

