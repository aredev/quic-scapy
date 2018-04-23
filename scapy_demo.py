import binascii
import json
import struct
import timeit
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
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from crypto.hkdf import Hkdf
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.string_to_ascii import string_to_ascii

destination_ip = "192.168.1.70"     # Home connectiopns
# destination_ip = "192.168.43.228"   # hotspot connections

# header lenght: 22 bytes


def send_chlo():
    print("Sending CHLO")
    chlo = QUICHeader()
    conf.L3socket = L3RawSocket

    # Store chlo for the key derivation
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo)

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    a = RejectionPacket(ans[0][1][1].payload.load)

    print(a.show())
    for key, value in a.fields.items():
        if "Server_Config_ID" in key:
            print("Key {} has this value {}".format(key, value.hex()))
            SessionInstance.get_instance().server_config_id = value
        if "Source_Address_Token" in key:
            SessionInstance.get_instance().source_address_token = value
        if "Server_Nonce" in key:
            SessionInstance.get_instance().server_nonce = value.hex()
        if "Public_Value" in key:
            # Has length 35, remove the first 4 bytes which only indicate the length of 32 bytes.
            SessionInstance.get_instance().peer_public_value = bytes.fromhex(value[3:].hex())

    # Store the server config
    # start of the server config value = header (22) + stream info (10) + 8 * keys (56). Now we are at the start of all the values
    # The following values are before the server config: STK (56) + SNO (52) + PROF (256), therefore it starts at 452 and has length 135

    SessionInstance.get_instance().scfg = extract_from_packet_as_bytestring(a, start=452, end=452+135)


send_chlo()


def send_first_ack():
    chlo = ACKPacket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


send_first_ack()


def send_second_ack():
    chlo = SecondACKPacket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


send_second_ack()


def send_version_proposal():
    version_proposal = VersionProposalPacket()
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

    # Lets just create the public key for DHKE
    dhke.set_up_my_keys()

    chlo.setfieldval('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes))

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    conf.L3socket = L3RawSocket
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo, start=31)   # CHLO from the CHLO tag, which starts at offset 26 (22 header + frame type + stream id + offset)

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    # Maybe we cannot assume that is just a version negotiation packet?
    a = AEADPacket(ans[0][1][1].payload.load)

    # Start key derivation
    packet_number = -1
    for key, value in a.fields.items():
        if "Diversification" in key:
            print("Key {} has this value {}".format(key, value.hex()))
            SessionInstance.get_instance().div_nonce = value
        if "Authentication" in key:
            # Add message authentication hash, needed for decryption just in case
            print("Message authentication hash has value {}".format(value.hex()))
            SessionInstance.get_instance().message_authentication_hash = value
        if "Packet" in key:
            packet_number = value

    dhke.generate_keys(SessionInstance.get_instance().peer_public_value)

    SessionInstance.get_instance().associated_data = extract_from_packet_as_bytestring(a, end=42)
    SessionInstance.get_instance().packet_number = extract_from_packet_as_bytestring(a, start=41, end=42)

    # Process the streams
    print("Frame processing for packet {}".format(packet_number))
    # print("Processing packet {}".format(extract_from_packet(a)))
    processor = FramesProcessor(extract_from_packet(a, start=54))
    processor.process()


send_full_chlo()


def send_encrypted_request():
    """
    Make an AEAD GET Request to example.org
    :return:
    """
    get_request = bytes.fromhex("800300002501250000000500000000FF418FF1E3C2E5F23A6BA0AB9EC9AE38110782848750839BD9AB7A85ED6988B4C7")
    # Todo: encrypt

    # Todo: send it





