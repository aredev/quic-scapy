import binascii
import struct
from _curses import raw

import socket
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Raw, bind_layers
from scapy.sendrecv import sr1, send, sr, sniff, srp
from scapy.supersocket import L3RawSocket
from scapy.utils import hexdump

from ACKPacket import ACKPacket
from AEADPacket import AEADPacket
from FullCHLOPacket import FullCHLOPacket
from QUIC import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from FramesProcessor import StreamProcessor, FramesProcessor
from VersionNegotiation import VersionNegotiationPacket
from VersionProposalPacket import VersionProposalPacket
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from crypto.hkdf import Hkdf
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytes
from util.string_to_ascii import string_to_ascii

destination_ip = "192.168.43.228"


def send_chlo():
    print("Sending CHLO")
    chlo = QUICHeader()

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    # Store chlo for the key derivation
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytes(chlo)

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = RejectionPacket(ans[0][1][1].payload.load)

    peer_public_value = ""
    for key, value in a.fields.items():
        if "Server_Config_ID" in key:
            print("Key {} has this value {}".format(key, value))
            SessionInstance.get_instance().server_config_id = value
        if "Source_Address_Token" in key:
            SessionInstance.get_instance().source_address_token = value
        if "Server_Nonce" in key:
            SessionInstance.get_instance().server_nonce = value
        if "Public_Value" in key:
            # Has length 35, remove the first 4 bytes which only indicate the length of 32 bytes.
            peer_public_value = value[3:]

    # Store the server config
    SessionInstance.get_instance().scfg = extract_from_packet_as_bytes(a, start=48, end=48+135)
    SessionInstance.get_instance().cert = extract_from_packet_as_bytes(a, start=90)

    # Start key derivation
    dhke.generate_keys(peer_public_value)


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
    chlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
    chlo.setfieldval('STK_Value', SessionInstance.get_instance().source_address_token)
    # chlo.setfieldval('PUBS_Value', SessionInstance.get_instance().public_value)

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    # L3RawSocket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = AEADPacket(ans[0][1][1].payload.load)

    # Process the streams
    processor = FramesProcessor(extract_from_packet(a, start=54))
    processor.process()

    print(a.show())
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

