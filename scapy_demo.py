import binascii
import json
import struct
import timeit
from _curses import raw

import socket
# from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Raw, bind_layers
from scapy.sendrecv import sr1, send, sr, sniff, srp
from scapy.supersocket import L3RawSocket
from scapy.utils import hexdump

from ACKPacket import ACKPacket
from AEADPacket import AEADPacket
from ConnectionInstance import ConnectionInstance, ConnectionEndpoint
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


# send_chlo()


def send_first_ack():
    chlo = ACKPacket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


# send_first_ack()


def send_second_ack():
    chlo = SecondACKPacket()
    conf.L3socket = L3RawSocket

    p = IP(dst=destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)


# send_second_ack()


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
    for key, value in a.fields.items():
        if "Diversification" in key:
            print("Key {} has this value {}".format(key, value.hex()))
            SessionInstance.get_instance().div_nonce = value
        if "Authentication" in key:
            # Add message authentication hash, needed for decryption just in case
            print("Message authentication hash has value {}".format(value.hex()))
            SessionInstance.get_instance().message_authentication_hash = value

    dhke.generate_keys(SessionInstance.get_instance().peer_public_value)

    SessionInstance.get_instance().associated_data = extract_from_packet_as_bytestring(a, end=42)
    SessionInstance.get_instance().packet_number = extract_from_packet_as_bytestring(a, start=41, end=42)

    # Process the streams
    processor = FramesProcessor(extract_from_packet(a, start=54))
    processor.process()


# send_full_chlo()


def send_encrypted_request():
    """
    Make an AEAD GET Request to example.org
    :return:
    """
    get_request = bytes.fromhex("800300002501250000000500000000FF418FF1E3C2E5F23A6BA0AB9EC9AE38110782848750839BD9AB7A85ED6988B4C7")
    # Todo: encrypt

    # Todo: send it


def connect_to_crypto_oracle():
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.connect(("localhost", 3030))
    json_example = {"mode": "decryption", "input": "503ea09bb060100e22e50d7ac42ab868d599018c09085ff90f5e2c096b5998685cb99e116611d83bca1d4bde4f3b5e253134027e97d104fef17bc3e3ab75ef6bf8bf22c72e5a590de75ebd416b50aa0be35f4df9b0af47d5b943a593838bba5891cb3271572f7fd16514493a17c0e205e0f6d27e17566241bcfa81507e717917164eb62374480ecaaff4137eafb6842a784f17278e148b44e42daa0d7c7f595f74054703a1d121d575611b03ebd011c6f30f3e971dfbfd014e3fa40b058655b6029ed3cc99b5539f7e1698b219c917fbb798500f66a78ab67c53ea7030688a945c6988096996bcd5a2786ab06327cba89e14f7c03e99f3609fb6976de1345ac46f4e26201421c7f582cbc595141bc36f8845e29faec80bfd0274adf72959ef69548df11e1823461d6ae78be741027b5b4325679ed4f223ed92645422cea8e894d251176406ab57c51eca12b131776340ac170d463994dafd2edee0fee69a031df4047b6012db416c500ba7b6b7e881eb2924805641237f26bf21fc06da786035546d9f5c61aeb9dc8e0b873b8a52bd2ce218bb52ba0258f494d994bf3c70093ef1f53b6367605cd1f08f90ee3b6504e3267282e5712913497f640a4a3dd265a7266bf3097076d4e5d09280e4e20d062aeac632a00fb9fa150f9ca2a2c553396f108d0fc334fc446733144d375f886c4ff20f4e8f2715764503c9f665ec090d3e2e0082a355165276ff461a38a14d94891439d39f86fb4e96b9dfa2c6f6bf2e846615b802763b295473045f03593a94cec030c56f2682f0494a624b91f0f79f8e164ab42c296ac1924f71bc09ef412eba8b2cdcef7a5380e332409dc878f84d20275f78034b5d76ab5480cd903bd98382ffa87ab337cab933f8eebc1c2101ebe13518552190205e4cfc7ec01d23ef2d60f661cf607d63ba221efbf92a99be1790dd7f93b754f491b74e746cb9e43fe68109084d01816d9c0c447024335955a0522d2d060b9962b7d3cc3231c8c56eff51051cb5c143a7d5fe6153d6222bb072939697106d850c86835c7304b2ee2e7f12b9c405da743c07d80ae3fef1a94c19e29cd6cf852e3a253487562083a82ac12f07a01fbef0cee0bdd63559c70fcb585a319520e0faee065680d0129cdc8eec807764b9cbaacdf9a67df035798d0f66ab8f3d2de69cf4076125267898cabbf8f5d67653e7cc5fb1c481365a866e768e4491f1611f287c3db92e4487c044e33319cbe5fe614d5f8f29909ca6347c2a8cee98edfc000a6c9be9a56460bd9d31e9436e65337c7d40b03b2860d64c327d6dc5723e40aba33ddedcef72adee19e83326f6a1e2bad2dfc29552ee8d69108b3d045bd8cd331a1114aef733114edd39bc7715bd958cdb4d560c1cdc9b5ff3b1e17fbd08d3f85d090e46014c5f8c9c11f42cf28cdb74872708219b2c1be992a04f184a61dcadb6", "additionalData": "0CD75487B7DA970F8158691F2702DB3EECF28F0D7B2B21C26A4960E5FE03E458D8513FF982F2B70F7106", "nonce": "88de280f0600000000000000", "key": "fb1cf61282250c428445e159d11d02aa"}
    # print(json.dumps(json_example).encode('utf-8'))
    # s.send(json.dumps(json_example).encode('utf-8'))
    #
    # s.close()
    # data = s.recv(1024)
    # print(data)
    response = ConnectionInstance.get_instance().send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(json_example).encode('utf-8'), True)
    print(response)
    print(response['status'])

connect_to_crypto_oracle()
