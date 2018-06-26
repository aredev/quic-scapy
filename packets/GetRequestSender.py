import json

from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.supersocket import L3RawSocket

from ACKNotificationPacket import AckNotificationPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from AEADRequestPacket import AEADRequestPacket
from FramesProcessor import FramesProcessor
from PacketNumberInstance import PacketNumberInstance
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from util.SessionInstance import SessionInstance
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii


class GetRequestSender:
    """
    Sends GET Requests
    """

    __instance = None
    __received_packets = 0
    __finished = False

    def __init__(self, instance) -> None:
        self.__instance = instance

    def packet_update(self, packet):
        # print("Received update from the Sniffer thread")
        a = AEADPacketDynamic(packet[0][1][1].payload.load)
        a.parse()
        print(">>>>>>>> Received packet with MAH: {}".format(a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))

        # Start key derixvation
        SessionInstance.get_instance().div_nonce = a.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)
        SessionInstance.get_instance().message_authentication_hash = a.get_field(
            AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
        packet_number = a.get_field(AEADFieldNames.PACKET_NUMBER)
        SessionInstance.get_instance().packet_number = packet_number
        SessionInstance.get_instance().largest_observed_packet_number = packet_number

        # print(">>>><<<!!!! Updating highest received packet number to {}".format(int(packet_number, 16)))
        # PacketNumberInstance.get_instance().update_highest_received_packet_number(int(packet_number, 16))

        dhke.generate_keys(SessionInstance.get_instance().peer_public_value,
                           SessionInstance.get_instance().shlo_received)

        SessionInstance.get_instance().associated_data = a.get_associated_data()
        SessionInstance.get_instance().packet_number = packet_number
        # Process the streams
        processor = FramesProcessor(split_at_nth_char(a.get_field(AEADFieldNames.ENCRYPTED_FRAMES)))
        processor.process(self)

        # print("GETTER received packets {}".format(self.__received_packets))
        if self.__received_packets < 3:
            self.__received_packets += 1
        else:
            self.__sniffer.remove_observer(self)
            self.send_ack()

    def make_get_request(self):
        get_request = "800300002501250000000500000000FF418FF1E3C2E5F23A6BA0AB9EC9AE38110782848750839BD9AB7A85ED6988B4C7"
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        ciphertext = CryptoManager.encrypt(bytes.fromhex(get_request), packet_number, self.__instance)

        # Send it to the server
        a = AEADRequestPacket()
        a.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        a.setfieldval("Public Flags", 0x18)
        a.setfieldval('Packet Number', packet_number)
        a.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[0:24]))

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(load=string_to_ascii(ciphertext[24:]))
        # self.__sniffer.add_observer(self)
        send(p)
        # print("Done sending...")

    def is_finished(self):
        return self.__finished

    def send_ack(self):
        ack = AckNotificationPacket()
        conf.L3socket = L3RawSocket

        ack.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        next_packet_number_int = PacketNumberInstance.get_instance().get_next_packet_number()
        next_packet_number_byte = int(next_packet_number_int).to_bytes(8, byteorder='little')
        next_packet_number_nonce = int(next_packet_number_int).to_bytes(2, byteorder='big')

        ack.setfieldval("Packet Number", next_packet_number_int)
        highest_received_packet_number = format(
            int(PacketNumberInstance.get_instance().get_highest_received_packet_number(), 16), 'x')

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
            'additionalData': "18" + SessionInstance.get_instance().connection_id + next_packet_number_byte.hex()[:4],
            # Fixed public flags 18 || fixed connection Id || packet number
            'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
        }

        # print("Ack request for encryption {}".format(request))

        ciphertext = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE,
                                                                    json.dumps(request).encode('utf-8'), True)
        ciphertext = ciphertext['data']
        # print("Ciphertext in ack {}".format(ciphertext))

        ack.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))
        SessionInstance.get_instance().nr_ack_send += 1

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ack / Raw(
            load=string_to_ascii(ciphertext[24:]))
        send(p)
        # print("After sending ack...")
        self.__finished = True
