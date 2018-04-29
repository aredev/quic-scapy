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
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from crypto.hkdf import Hkdf
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii

# header lenght: 22 bytes


def send_chlo():
    print("Sending CHLO")
    chlo = QUICHeader()
    conf.L3socket = L3RawSocket

    # Store chlo for the key derivation
    SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo)

    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())
    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    ans, _ = sr(p)
    a = RejectionPacket(ans[0][1][1].payload.load)

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

    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    send(p)


send_first_ack()


def send_second_ack():
    chlo = SecondACKPacket()
    conf.L3socket = L3RawSocket

    chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    send(p)


# send_second_ack()


def send_ack_for_encrypted_message():
    ack = AckNotificationPacket()
    conf.L3socket = L3RawSocket

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
    if SessionInstance.get_instance().nr_ack_send == 0:
        ack_body += str(highest_received_packet_number).zfill(2)
        ack_body += "00"
        ack_body += "01"
    keys = SessionInstance.get_instance().keys

    request = {
        'mode': 'encryption',
        'input': ack_body,
        'key': keys['key1'].hex(),  # For encryption, we use my key
        'additionalData': "18d75487b7da970f81" + next_packet_number_byte.hex()[:4], # Fixed public flags 18 || fixed connection Id || packet number
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

    # _thread.start_new_thread(start_sniff_thread, ())

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
    # Maybe we cannot assume that is just a version negotiation packet?
    send(p)
    sniff(prn=handle_received_encrypted_packet, filter="udp", store=0, count=2)
    # send_ping()
    send_ack_for_encrypted_message()


send_full_chlo()


def send_encrypted_request():
    """
    Make an AEAD GET Request to example.org
    :return:
    """
    print("Sending GET Request")
    get_request = "800300002501250000000500000000FF418FF1E3C2E5F23A6BA0AB9EC9AE38110782848750839BD9AB7A85ED6988B4C7"
    packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
    ciphertext = CryptoManager.encrypt(bytes.fromhex(get_request), packet_number)

    # Send it to the server
    a = AEADRequestPacket()
    a.setfieldval("Public Flags", 0x18)
    a.setfieldval('Packet Number', packet_number)
    a.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[0:24]))

    p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(load=string_to_ascii(ciphertext[24:]))
    send(p)
    sniff(prn=handle_received_encrypted_packet, filter="udp", store=0, count=2)
    send_ack_for_encrypted_message()
    # # a = AEADRequestPacket(ans[0][1][1].payload.load)
    # print("Handle GET Response")
    # sniff(prn=handle_received_encrypted_packet, filter="udp", store=0, count=2)
    # send_ack_for_encrypted_message()


    # handle this.

    # print(a)
    # No div nonce, so only flags || CID || packetnumber
    # SessionInstance.get_instance().associated_data = extract_from_packet_as_bytestring(a, end=10)St
    # SessionInstance.get_instance().packet_number = extract_from_packet_as_bytestring(a, start=9, end=10)
    # print(SessionInstance.get_instance().packet_number)
    #
    # # Process the streams
    # # print("Processing packet {}".format(extract_from_packet(a)))
    # processor = FramesProcessor(extract_from_packet(a, start=22))
    # processor.process()


send_encrypted_request()
send_ack_for_encrypted_message()
send_encrypted_request()
send_ack_for_encrypted_message()
send_encrypted_request()
send_ack_for_encrypted_message()

# handle_received_encrypted_packet(None)
