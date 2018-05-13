import _thread
import json
import socket
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Raw, bind_layers
from scapy.sendrecv import sr1, send, sr, sniff, srp
from scapy.supersocket import L3RawSocket
from scapy.utils import hexdump

from ACKNotificationPacket import AckNotificationPacket
from ACKPacket import ACKPacket
from AEADPacket import AEADPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from AEADRequestPacket import AEADRequestPacket
from FullCHLOPacket import FullCHLOPacket
from PacketNumberInstance import PacketNumberInstance
from PingPacket import PingPacket
from QUIC import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from FramesProcessor import StreamProcessor, FramesProcessor
from ThirdACKPacket import ThirdACKPacket
from VersionNegotiation import VersionNegotiationPacket
from VersionProposalPacket import VersionProposalPacket
from caching.CacheInstance import CacheInstance
from caching.SessionModel import SessionModel
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from crypto.hkdf import Hkdf
from packets.GetRequestSender import GetRequestSender
from sniffer.sniffer import Sniffer
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii
import random

# header lenght: 22 bytes

sniffer = Sniffer()
sniffer.start()


def send_chlo():
    PacketNumberInstance.get_instance().reset()
    conn_id = random.getrandbits(64)
    SessionInstance.get_instance().connection_id_as_number = conn_id
    SessionInstance.get_instance().connection_id = str(format(conn_id, 'x'))
    print(SessionInstance.get_instance().connection_id)

    print("Sending CHLO")
    chlo = QUICHeader()
    conf.L3socket = L3RawSocket

    chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    # Store chlo for the key derivation
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo)
    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    a = RejectionPacket(ans[0][1][1].payload.load)

    for key, value in a.fields.items():
        if "Server_Config_ID" in key:
            SessionInstance.get_instance().server_config_id = value
        if "Source_Address_Token" in key:
            SessionInstance.get_instance().source_address_token = value
        if "Server_Nonce" in key:
            SessionInstance.get_instance().server_nonce = value.hex()
        if "Public_Value" in key:
            # Has length 35, remove the first 4 bytes which only indicate the length of 32 bytes.
            SessionInstance.get_instance().peer_public_value = bytes.fromhex(value[3:].hex())

    # Store it locally, such that in a next CHLO we can directly use it.
    CacheInstance.get_instance().add_session_model(
        SessionModel(
            source_address_token=SessionInstance.get_instance().source_address_token.hex(),
            server_nonce=SessionInstance.get_instance().server_nonce,
            server_config_id=SessionInstance.get_instance().server_config_id.hex(),
            public_value=SessionInstance.get_instance().peer_public_value.hex()
        )
    )

    # Store the server config
    # start of the server config value = header (22) + stream info (10) + 8 * keys (56). Now we are at the start of all the values
    # The following values are before the server config: STK (56) + SNO (52) + PROF (256), therefore it starts at 452 and has length 135

    SessionInstance.get_instance().scfg = extract_from_packet_as_bytestring(a, start=452, end=452+135)


send_chlo()


def send_first_ack():
    chlo = ACKPacket()
    conf.L3socket = L3RawSocket

    chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    print("Associated data {}".format(associated_data))
    print("Body {}".format(body))

    message_authentication_hash = FNV128A().generate_hash(associated_data, body, True)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    print("Sending first ACK...")

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    send(p)


send_first_ack()


def send_second_ack():
    chlo = SecondACKPacket()
    conf.L3socket = L3RawSocket

    chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    send(p)


# send_second_ack()


def send_ack_for_encrypted_message():
    ack = AckNotificationPacket()
    conf.L3socket = L3RawSocket

    ack.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

    next_packet_number_int = PacketNumberInstance.get_instance().get_next_packet_number()
    next_packet_number_byte = int(next_packet_number_int).to_bytes(8, byteorder='little')
    next_packet_number_nonce = int(next_packet_number_int).to_bytes(2, byteorder='big')

    ack.setfieldval("Packet Number", next_packet_number_int)
    highest_received_packet_number = format(PacketNumberInstance.get_instance().get_highest_received_packet_number(), 'x')

    ack_body = "40"
    ack_body += str(highest_received_packet_number).zfill(2)
    ack_body += "0062"
    ack_body += str(highest_received_packet_number).zfill(2)
    ack_body += "00"
    # not sure yet if we can remove this?
    # if SessionInstance.get_instance().nr_ack_send == 0:
    #     ack_body += str(highest_received_packet_number).zfill(2)
    #     ack_body += "00"
    #     ack_body += "01"
    keys = SessionInstance.get_instance().keys

    request = {
        'mode': 'encryption',
        'input': ack_body,
        'key': keys['key1'].hex(),  # For encryption, we use my key
        'additionalData': "18" + SessionInstance.get_instance().connection_id + next_packet_number_byte.hex()[:4], # Fixed public flags 18 || fixed connection Id || packet number
        'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
    }

    print("Ack request for encryption {}".format(request))

    ciphertext = ConnectionInstance.get_instance().send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(request).encode('utf-8'), True)
    ciphertext = ciphertext['data']
    print("Ciphertext in ack {}".format(ciphertext))

    ack.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))
    SessionInstance.get_instance().nr_ack_send += 1

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ack / Raw(load=string_to_ascii(ciphertext[24:]))
    send(p)


def handle_received_encrypted_packet(packet):
    a = AEADPacketDynamic(packet[0][1][1].payload.load)
    a.parse()
    print(">>>>>>>> Received packet with MAH: {}".format(a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))

    # Start key derixvation
    SessionInstance.get_instance().div_nonce = a.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)
    SessionInstance.get_instance().message_authentication_hash = a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
    packet_number = a.get_field(AEADFieldNames.PACKET_NUMBER)
    SessionInstance.get_instance().packet_number = packet_number
    SessionInstance.get_instance().largest_observed_packet_number = packet_number

    print(">>>><<<!!!! Updating highest received packet number to {}".format(int(packet_number, 16)))
    PacketNumberInstance.get_instance().update_highest_received_packet_number(int(packet_number, 16))

    dhke.generate_keys(SessionInstance.get_instance().peer_public_value, SessionInstance.get_instance().shlo_received)

    SessionInstance.get_instance().associated_data = a.get_associated_data()
    SessionInstance.get_instance().packet_number = packet_number

    # Process the streams
    processor = FramesProcessor(split_at_nth_char(a.get_field(AEADFieldNames.ENCRYPTED_FRAMES)))
    processor.process()


def send_ping():
    print("Sending ping message...")
    ping = PingPacket()
    ping.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

    packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
    ciphertext = CryptoManager.encrypt(bytes.fromhex("07"), packet_number)

    ping.setfieldval('Packet Number', packet_number)
    ping.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))

    conf.L3socket = L3RawSocket
    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ping / Raw(load=string_to_ascii(ciphertext[24:]))
    # Maybe we cannot assume that is just a version negotiation packet?
    send(p)


def send_full_chlo():
    chlo = FullCHLOPacket()

    chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
    chlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
    chlo.setfieldval('STK_Value', SessionInstance.get_instance().source_address_token)

    # Lets just create the public key for DHKE
    dhke.set_up_my_keys()

    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())
    chlo.setfieldval('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes))

    associated_data = extract_from_packet(chlo, end=15)
    body = extract_from_packet(chlo, start=27)

    message_authentication_hash = FNV128A().generate_hash(associated_data, body)
    chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

    conf.L3socket = L3RawSocket
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo, start=31)   # CHLO from the CHLO tag, which starts at offset 26 (22 header + frame type + stream id + offset)

    print("Send full CHLO")

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    # Maybe we cannot assume that is just a version negotiation packet?
    ans, _ = sr(p)
    handle_received_encrypted_packet(ans)
    send_ack_for_encrypted_message()


send_full_chlo()


def close_connection():
    """
    We do this the friendly way by means of a Go Away
    :return:
    """
    frame_data = "03"           # frame type
    frame_data += "00000000"    # error code, no error
    frame_data += "00000000"    # latest responded stream Id
    frame_data += "0000"        # No reason therefore length of 0

    # encrypt it
    packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
    ciphertext = CryptoManager.encrypt(bytes.fromhex(frame_data), packet_number)

    a = AEADRequestPacket()
    a.setfieldval("Public Flags", 0x18)
    a.setfieldval('Packet Number', packet_number)
    a.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[0:24]))
    a.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

    print("Closing connection {}".format(SessionInstance.get_instance().connection_id))

    print("With ciphertext {}".format(ciphertext))
    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(load=string_to_ascii(ciphertext[24:]))
    # ans, _ = sr(p, count=3)
    send(p)


def send_encrypted_request():
    """
    Make an AEAD GET Request to example.org
    :return:
    """
    print("Sending GET Request")
    getter = GetRequestSender(sniffer)
    getter.make_get_request()
    print("Get request finished?")

send_encrypted_request()
# send_ack_for_encrypted_message()
close_connection()

# send_encrypted_request()
# send_ack_for_encrypted_message()
# send_encrypted_request()
# send_ack_for_encrypted_message()

# handle_received_encrypted_packet(None)
