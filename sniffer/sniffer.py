import json
import logging
import threading
import time
from threading import Thread

from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sniff, send
from scapy.supersocket import L3RawSocket

from ACKNotificationPacket import AckNotificationPacket
from ACKPacket import ACKPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from FramesProcessor import FramesProcessor
from PacketNumberInstance import PacketNumberInstance
from RejectionPacket import RejectionPacket
from caching.CacheInstance import CacheInstance
from caching.SessionModel import SessionModel
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet_as_bytestring, extract_from_packet
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii


class Sniffer(Thread):

    __observers = []
    __stop_sniffing = False
    __packet_instance = None
    __logger: logging = None

    def set_session_instance(self, instance, logger):
        self.__packet_instance = instance
        self.__logger = logger

    def run(self) -> None:
        try:
            self.__stop_sniffing = False
            print("Sniffing started")
            nr_packets = sniff(prn=self.inform_observer, filter="udp and dst port 61250 and src port 6121", stop_filter=self.do_i_need_to_stop)
            print("Sniffing stopped with {}".format(nr_packets))
        except Exception as err:
            print("Exception has occured! {}".format(err))
            self.__logger.exception(err)

    def add_observer(self, observer):
        self.__observers.append(observer)

    def __handle_encrypted_packet(self, a):
        SessionInstance.get_instance().div_nonce = a.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)
        SessionInstance.get_instance().message_authentication_hash = a.get_field(
            AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
        packet_number = a.get_field(AEADFieldNames.PACKET_NUMBER)
        SessionInstance.get_instance().packet_number = packet_number
        # print("Packet Number {}".format(packet_number))
        SessionInstance.get_instance().largest_observed_packet_number = packet_number
        PacketNumberInstance.get_instance().highest_received_packet_number = packet_number
        SessionInstance.get_instance().associated_data = a.get_associated_data()
        # print("Associated Data {}".format(SessionInstance.get_instance().associated_data))
        ciphertext = split_at_nth_char(a.get_field(AEADFieldNames.ENCRYPTED_FRAMES))

        print("Received peer public value {}".format(SessionInstance.get_instance().peer_public_value))

        # Only generate a new set of initial keys when we receive a new REJ
        current_app_key = SessionInstance.get_instance().app_keys
        self.__logger.info("Currently stored app key {}".format(current_app_key))
        self.__logger.info("Last received REJ")
        if current_app_key['type'] != "REJ" \
                or current_app_key['mah'] != SessionInstance.get_instance().last_received_rej\
                or SessionInstance.get_instance().zero_rtt:
            # If the generated key does not comply with the previously received REJ, then create a new set of keys
            # Or if it is the first set of keys. Otherwise we just use the previous set of keys.
            key = dhke.generate_keys(SessionInstance.get_instance().peer_public_value,
                               SessionInstance.get_instance().shlo_received, self.__logger)
            SessionInstance.get_instance().app_keys['type'] = "REJ"
            SessionInstance.get_instance().app_keys['mah'] = SessionInstance.get_instance().last_received_rej
            SessionInstance.get_instance().app_keys['key'] = key
        # SessionInstance.get_instance().packet_number = packet_number

        # Process the streams
        processor = FramesProcessor(ciphertext)
        return processor.process(logger=self.__logger)

    def __handle_rej_packet(self, a):
        self.__logger.info("Storing REJ information from packet {}".format(a.getfieldval('Message Authentication Hash')))
        for key, value in a.fields.items():
            if "Server_Config_ID" in key:
                SessionInstance.get_instance().server_config_id = value
                self.__logger.info("STORING: ServerConfigId {}".format(value))
            if "Source_Address_Token" in key:
                SessionInstance.get_instance().source_address_token = value
                self.__logger.info("STORING: SATKOK {}".format(value))

            if "Server_Nonce" in key:
                SessionInstance.get_instance().server_nonce = value.hex()
                self.__logger.info("STORING: SNONCE {}".format(value))
            if "Public_Value" in key:
                # Has length 35, remove the first 4 bytes which only indicate the length of 32 bytes.
                SessionInstance.get_instance().peer_public_value = bytes.fromhex(value[3:].hex())
                self.__logger.info("Public value used for DHKE {}".format(value[3:].hex()))

        # Store it locally, such that in a next CHLO we can directly use it.
        CacheInstance.get_instance().add_session_model(
            SessionModel(
                source_address_token=SessionInstance.get_instance().source_address_token.hex(),
                server_nonce=SessionInstance.get_instance().server_nonce,
                server_config_id=SessionInstance.get_instance().server_config_id.hex(),
                public_value=SessionInstance.get_instance().peer_public_value.hex(),
                connection_id=SessionInstance.get_instance().connection_id
            )
        )

        if SessionInstance.get_instance().scfg == "":
            SessionInstance.get_instance().scfg = extract_from_packet_as_bytestring(a, start=452, end=452+135)
        # print("Processing of REJ completed.")

    def inform_observer(self, packet):
        parsed_packet = AEADPacketDynamic(packet[0][1][1].payload.load)
        parsed_packet.parse()
        if parsed_packet.get_field(AEADFieldNames.CID) == SessionInstance.get_instance().connection_id:
            self.__logger.info("Received packet with MAH {}".format(parsed_packet.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))
            print(">>>>>>>> Received packet with MAH: {}".format(parsed_packet.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))
            self.__packet_instance.highest_received_packet_number = parsed_packet.get_field(AEADFieldNames.PACKET_NUMBER)

            # Catch the Public Reset packet, flags == 0x0e && TAG == PRST (50525354)
            # print("Parsed packet Public Flags {}".format(parsed_packet.get_field(AEADFieldNames.PUBLIC_FLAGS)))
            if parsed_packet.get_field(AEADFieldNames.PUBLIC_FLAGS) == "0e":
                # check if the tag is equal to the PRST
                tag = parsed_packet.packet_body[9:13]
                if tag == b'PRST':
                    self.__logger.info("Parsed as PRST")
                    # Public Reset Packet
                    for observer in self.__observers:
                        observer.update("", "PRST")
                    return

            if SessionInstance.get_instance().shlo_received or parsed_packet.has_field(AEADFieldNames.DIVERSIFICATION_NONCE):
                threading.Thread(target=self.__send_encrypted_ack, args=()).start()
                result = self.__handle_encrypted_packet(parsed_packet)
                self.__logger.info("Parsed as encrypted packet")
                for observer in self.__observers:
                    # print("Result {}".format(result))
                    observer.update("", result)
            else:
                # Add a check if it is really a REJ or just garbage
                try:
                    threading.Thread(target=self.__send_unencrypted_ack, args=()).start()
                    rej_packet = RejectionPacket(packet[0][1][1].payload.load)
                    rej_tag = rej_packet.getfieldval('Tag_1')
                    if rej_tag == b'REJ\x00':
                        # print("REJ Received")
                        SessionInstance.get_instance().last_received_rej = parsed_packet.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
                        self.__logger.info("Parsed as REJ packet")
                        # if not SessionInstance.get_instance().currently_sending_zero_rtt:
                        self.__handle_rej_packet(rej_packet)
                        for observer in self.__observers:
                            observer.update("", "REJ")
                    else:
                        self.__logger.info("Parsed as Garbage")
                        threading.Thread(target=self.__send_unencrypted_ack, args=()).start()
                        # print("Garbage received, ack has been sent.")
                except Exception:
                    self.__logger.info("Parsed as closed. Not a REJ packet.")
                    # Considered as garbage.
                    # Maybe its not a REJ packet
                    # for observer in self.__observers:
                    #     observer.update("", "closed")
        else:
            self.__logger.info("Discarding old connection id message received")

    def __send_unencrypted_ack(self):
        chlo = ACKPacket()
        conf.L3socket = L3RawSocket

        chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

        # print("First Ack Packet Number {}".format(int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16)))
        chlo.setfieldval('Largest Acked', int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16))
        chlo.setfieldval('First Ack Block Length', int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16))

        associated_data = extract_from_packet(chlo, end=15)
        body = extract_from_packet(chlo, start=27)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body, True)
        chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
        send(p)

    def __send_encrypted_ack(self):
        ack = AckNotificationPacket()
        conf.L3socket = L3RawSocket
        ack.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        next_packet_number_int = PacketNumberInstance.get_instance().get_next_packet_number()
        next_packet_number_byte = int(next_packet_number_int).to_bytes(8, byteorder='little')
        next_packet_number_nonce = int(next_packet_number_int).to_bytes(2, byteorder='big')
        # print("Sending encrypted ack for packet number {}".format(next_packet_number_int))

        ack.setfieldval("Packet Number", next_packet_number_int)
        highest_received = PacketNumberInstance.get_instance().get_highest_received_packet_number()
        # print("Higheste {}".format(highest_received))
        highest_received_packet_number = format(int(highest_received, 16), 'x')

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
        if keys:
            request = {
                'mode': 'encryption',
                'input': ack_body,
                'key': keys['key1'].hex(),  # For encryption, we use my key
                'additionalData': "18" + SessionInstance.get_instance().connection_id + next_packet_number_byte.hex()[:4], # Fixed public flags 18 || fixed connection Id || packet number
                'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
            }
        else:
            request = {
                'mode': 'encryption',
                'input': ack_body,
                'key': "d309c2ddf54fdb0c34e9ae8f2aa5d0a4",  # Just use a fixed, invalid key
                'additionalData': "18" + SessionInstance.get_instance().connection_id + next_packet_number_byte.hex()[
                                                                                        :4],
            # Fixed public flags 18 || fixed connection Id || packet number
                'nonce': "7a40a2e70600000000000000" # Just use a fixed, invalid nonce.
            }

        # print("Ack request for encryption {}".format(request))

        ciphertext = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(request).encode('utf-8'), True)
        ciphertext = ciphertext['data']
        # print("Ciphertext in ack {}".format(ciphertext))

        ack.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))
        SessionInstance.get_instance().nr_ack_send += 1

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ack / Raw(load=string_to_ascii(ciphertext[24:]))
        send(p)

    def do_i_need_to_stop(self, packet):
        return self.__stop_sniffing

    def remove_observer(self, observer):
        self.__observers.remove(observer)

    def stop_sniffing(self):
        # print("Requested to stop sniffing")
        self.__stop_sniffing = True
