import datetime
import json
import random
from collections import Counter
from statistics import median, mean

from peewee import OperationalError
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Raw
from scapy.packet import fuzz
from scapy.sendrecv import send, sr
from scapy.supersocket import L3RawSocket
from tqdm import tqdm

from ACKNotificationPacket import AckNotificationPacket
from ACKPacket import ACKPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from AEADRequestPacket import AEADRequestPacket
from DynamicCHLOPacket import DynamicCHLOPacket
from FramesProcessor import FramesProcessor
from FullCHLOPacket import FullCHLOPacket
from FullCHLOPacketNoPadding import FullCHLOPacketNoPadding
from PacketNumberInstance import PacketNumberInstance
from PingPacket import PingPacket
from QUIC import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from caching.CacheInstance import CacheInstance
from caching.SessionModel import SessionModel
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from connection.LearnerConnectionInstance import LearnerConnectionInstance
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, \
    ZeroRTTCHLOEvent, ResetEvent
from sniffer.sniffer import Sniffer
from util.NonDeterminismCatcher import NonDeterminismCatcher
from util.RespondDummy import RespondDummy
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii
import time
import logging
import os


# header lenght: 22 bytes

class Scapy:

    sniffer = None
    learner = None
    response_times = []
    processed = False
    start_time = None
    TIMEOUT = 0.3263230323791504 * 5
    result = ""
    logger = None
    run_results = []
    current_event = None
    run = ""
    ndc = None
    run_events = []
    previous_result = ""

    def __init__(self) -> None:
        currenttime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = 'log_{}.txt'.format(currenttime)
        logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

        self.sniffer = Sniffer()
        self.sniffer.start()
        self.sniffer.set_session_instance(PacketNumberInstance.get_instance(), self.logger)
        self.ndc = NonDeterminismCatcher(self.logger)

        dhke.set_up_my_keys()
        self.learner = RespondDummy()
        try:
            pass
            # self.learner = LearnerConnectionInstance()
            # self.learner.add_observer(self)
            # self.learner.set_up_communication_server()
        except Exception as err:
            self.logger.exception(err)

    def reset(self, reset_server, reset_run=True):
        # also reset the server
        if reset_server:
            filename = str(time.time())
            open('resets/{}'.format(filename), 'a')
            time.sleep(8)

        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.
            self.run_events = []

        self.run = ""
        self.previous_result = ""
        PacketNumberInstance.get_instance().reset()
        conn_id = random.getrandbits(64)
        SessionInstance.get_instance().shlo_received = False
        SessionInstance.get_instance().scfg = ""
        SessionInstance.get_instance().zero_rtt = False
        self.logger.info("Changing CID from {}".format(SessionInstance.get_instance().connection_id))
        SessionInstance.get_instance().connection_id_as_number = conn_id
        SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(16))  # Pad to 16 chars
        self.logger.info("To {}".format(SessionInstance.get_instance().connection_id))

    def send_chlo(self, only_reset):
        print("Only reset? {}".format(only_reset))
        self.reset(only_reset)

        if only_reset:
            self.learner.respond("RESET")
            return

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
        self.sniffer.add_observer(self)
        # chlo = fuzz(chlo)
        # print(chlo.show())
        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
        send(p)
        self.wait_for_signal_or_expiration()

        self.processed = False
        self.sniffer.remove_observer(self)

    def wait_for_signal_or_expiration(self):
        # wait for a specific time otherwise
        start = time.time()
        expired = False
        while not self.processed and not expired:
            if time.time() - start >= self.TIMEOUT:
                expired = True
        if expired:
            print("General expired")
            if len(self.run_results) == 3:
                # Get the majority element
                c = Counter(self.run_results)
                value, count = c.most_common()[0]
                self.learner.respond(value)
                self.logger.info("General expired")
                self.run += str(self.current_event)
                self.ndc.add_run(self.run, value)
                self.run_results = []
                self.previous_result = value
                # self.reset(True, False)    # Reset the server
            else:
                self.run_results.append("EXP")
                self.logger.info("Received first time {} launching again".format("EXP"))
                time.sleep(2)
                self.logger.info("Run events {}".format(self.run_events))
                # if not isinstance(self.current_event, SendGETRequestEvent):
                self.send(self.current_event, True)
        else:
            print("General response {}".format(self.result))
            if len(self.run_results) == 3:
                # Get the majority element
                c = Counter(self.run_results)
                value, count = c.most_common()[0]
                if isinstance(self.current_event, SendGETRequestEvent):
                    # If there is atleast one HTTP response, then it is a HTTP response.
                    # Because the server didn't respond to three subsequent GET requests.
                    if "http" in self.run_results:
                        value = "http"
                    if "REJ" in self.run_results:
                        if self.run_results.count("REJ") == len(self.run_results):
                            value = "EXP"
                        else:
                            # remove all the REJs
                            value = list(filter(lambda a: a != 'REJ', self.run_results))[0]
                    if (self.previous_result == "shlo" or self.previous_result == "http") and "http" not in self.run_results:
                        value = "http"

                self.learner.respond(value)
                self.logger.info("General response {}".format(value))
                self.run += str(self.current_event)
                self.ndc.add_run(self.run, value)
                self.previous_result = value
                self.run_results = []
                # self.reset(True, False)
            else:
                self.run_results.append(self.result)
                self.logger.info("Received first time {} launching again".format(self.result))
                time.sleep(2)
                self.logger.info("Run events {}".format(self.run_events))
                # if not isinstance(self.current_event, SendGETRequestEvent):
                self.send(self.current_event, True)

        self.logger.info("=========== Request Finished ===========")
        self.result = ""

    def send_first_ack(self):
        chlo = ACKPacket()
        conf.L3socket = L3RawSocket

        chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        chlo.setfieldval("Packet Number", PacketNumberInstance.get_instance().get_next_packet_number())

        print("First Ack Packet Number {}".format(int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16)))
        chlo.setfieldval('Largest Acked', int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16))
        chlo.setfieldval('First Ack Block Length', int(str(PacketNumberInstance.get_instance().highest_received_packet_number), 16))

        # chlo.setfieldval('Largest Acked', 3)
        # chlo.setfieldval('First Ack Block Length', 3)

        associated_data = extract_from_packet(chlo, end=15)
        body = extract_from_packet(chlo, start=27)

        print("Associated data {}".format(associated_data))
        print("Body {}".format(body))

        message_authentication_hash = FNV128A().generate_hash(associated_data, body, True)
        chlo.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))

        print("Sending first ACK...")

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / chlo
        send(p)

    def send_second_ack(self):
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

    def send_ack_for_encrypted_message(self):
        ack = AckNotificationPacket()
        conf.L3socket = L3RawSocket

        ack.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        next_packet_number_int = PacketNumberInstance.get_instance().get_next_packet_number()
        next_packet_number_byte = int(next_packet_number_int).to_bytes(8, byteorder='little')
        next_packet_number_nonce = int(next_packet_number_int).to_bytes(2, byteorder='big')
        print("Sending encrypted ack for packet number {}".format(next_packet_number_int))

        ack.setfieldval("Packet Number", next_packet_number_int)
        highest_received_packet_number = format(int(PacketNumberInstance.get_instance().get_highest_received_packet_number(), 16), 'x')

        ack_body = "40"
        ack_body += str(highest_received_packet_number).zfill(2)
        ack_body += "0062"
        ack_body += str(highest_received_packet_number).zfill(2)
        ack_body += "00"
        # not sure yet if we can remove this?

        keys = SessionInstance.get_instance().keys

        request = {
            'mode': 'encryption',
            'input': ack_body,
            'key': keys['key1'].hex(),  # For encryption, we use my key
            'additionalData': "18" + SessionInstance.get_instance().connection_id + next_packet_number_byte.hex()[:4], # Fixed public flags 18 || fixed connection Id || packet number
            'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
        }

        print("Ack request for encryption {}".format(request))

        ciphertext = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(request).encode('utf-8'), True)
        ciphertext = ciphertext['data']
        print("Ciphertext in ack {}".format(ciphertext))

        ack.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))
        SessionInstance.get_instance().nr_ack_send += 1

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ack / Raw(load=string_to_ascii(ciphertext[24:]))
        send(p)

    def handle_received_encrypted_packet(self, packet):
        a = AEADPacketDynamic(packet[0][1][1].payload.load)
        a.parse()
        print(">>>>>>>> Received packet with MAH: {}".format(a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)))

        # Start key derixvation
        SessionInstance.get_instance().div_nonce = a.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)
        SessionInstance.get_instance().message_authentication_hash = a.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)
        packet_number = a.get_field(AEADFieldNames.PACKET_NUMBER)
        SessionInstance.get_instance().packet_number = packet_number
        print("Packet Number {}".format(packet_number))
        SessionInstance.get_instance().largest_observed_packet_number = packet_number
        SessionInstance.get_instance().associated_data = a.get_associated_data()
        print("Associated Data {}".format(SessionInstance.get_instance().associated_data))
        ciphertext = split_at_nth_char(a.get_field(AEADFieldNames.ENCRYPTED_FRAMES))

        print("Received peer public value {}".format(SessionInstance.get_instance().peer_public_value))
        dhke.generate_keys(SessionInstance.get_instance().peer_public_value, SessionInstance.get_instance().shlo_received)
        # SessionInstance.get_instance().packet_number = packet_number

        # Process the streams
        processor = FramesProcessor(ciphertext)
        processor.process()

    def send_ping(self):
        print("Sending ping message...")
        ping = PingPacket()
        ping.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        ciphertext = CryptoManager.encrypt(bytes.fromhex("07"), packet_number, SessionInstance.get_instance())

        ping.setfieldval('Packet Number', packet_number)
        ping.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[:24]))

        conf.L3socket = L3RawSocket
        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / ping / Raw(load=string_to_ascii(ciphertext[24:]))
        # Maybe we cannot assume that is just a version negotiation packet?
        send(p)

    def send_full_chlo(self):
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
        # ans, _ = sr(p)
        self.sniffer.add_observer(self)
        send(p)
        self.wait_for_signal_or_expiration()

        self.processed = False
        self.sniffer.remove_observer(self)

    def close_connection(self):
        """
        We do this the unfriendly way, since GoAway does not work. friendly way by means of a Go Away
        :return:
        """
        frame_data = "02"           # frame type
        frame_data += "00000000"    # error code, no error
        # frame_data += "00000000"    # latest responded stream Id
        frame_data += "0000"        # No reason therefore length of 0

        # encrypt it
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        ciphertext = CryptoManager.encrypt(bytes.fromhex(frame_data), packet_number, SessionInstance.get_instance(), self.logger)

        a = AEADRequestPacket()
        a.setfieldval("Public Flags", 0x18)
        a.setfieldval('Packet Number', packet_number)
        a.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[0:24]))
        a.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        self.logger.info("Closing connection {}".format(SessionInstance.get_instance().connection_id))

        self.logger.info("With ciphertext {}".format(ciphertext))
        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(load=string_to_ascii(ciphertext[24:]))
        # ans, _ = sr(p, count=3)
        send(p)
        self.previous_result = "closed"
        self.learner.respond("closed")
        time.sleep(1)

    def send_full_chlo_to_existing_connection(self):
        """
        Is it sent encrypted?
        :return:
        """
        try:
            previous_session = SessionModel.get(SessionModel.id == 1)
            self.logger.info("Server config Id {}".format(previous_session.server_config_id))

            # The order is important!
            tags = [
                {
                    'name': 'PAD',
                    'value': '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                },
                {
                    'name': 'SNI',
                    'value': '7777772e6578616d706c652e6f7267'
                },
                {
                    'name': 'STK',
                    'value': previous_session.source_address_token
                },
                {
                    'name': 'SNO',
                    'value': previous_session.server_nonce
                },
                {
                    'name': 'VER',
                    'value': '00000000'
                },
                {
                    'name': 'CCS',
                    'value': '01e8816092921ae87eed8086a2158291'
                },
                {
                    'name': 'NONC',
                    'value': '5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830'
                },
                {
                    'name': 'AEAD',
                    'value': '41455347'  # AESGCM12
                },
                {
                    'name': 'SCID',
                    'value': previous_session.server_config_id
                },
                {
                    'name': 'PDMD',
                    'value': '58353039'
                },
                {
                    'name': 'ICSL',
                    'value': '1e000000'
                },
                {
                    'name': 'PUBS',
                    'value': '96D49F2CE98F31F053DCB6DFE729669385E5FD99D5AA36615E1A9AD57C1B090C'
                },
                {
                    'name': 'MIDS',
                    'value': '64000000'
                },
                {
                    'name': 'KEXS',
                    'value': '43323535'  # C25519
                },
                {
                    'name': 'XLCT',
                    'value': '7accfb0fbd674011'
                },
                {
                    'name': 'CFCW',
                    'value': '00c00000'
                },
                {
                    'name': 'SFCW',
                    'value': '00800000'
                },
            ]

            d = DynamicCHLOPacket(tags)
            body = d.build_body()
            PacketNumberInstance.get_instance().reset()

            conn_id = random.getrandbits(64)
            SessionInstance.get_instance().server_nonce = previous_session.server_nonce
            SessionInstance.get_instance().connection_id_as_number = conn_id
            SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(8))
            SessionInstance.get_instance().peer_public_value = bytes.fromhex(previous_session.public_value)
            self.logger.info("Using connection Id {}".format(SessionInstance.get_instance().connection_id))
            SessionInstance.get_instance().shlo_received = False
            SessionInstance.get_instance().zero_rtt = True
            #
            a = FullCHLOPacketNoPadding()
            a.setfieldval('Packet Number', PacketNumberInstance.get_instance().get_next_packet_number())
            a.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

            # # Lets just create the public key for DHKE
            dhke.set_up_my_keys()

            associated_data = extract_from_packet(a, end=15)
            body_mah = [body[i:i + 2] for i in range(0, len(body), 2)]
            message_authentication_hash = FNV128A().generate_hash(associated_data, body_mah)

            conf.L3socket = L3RawSocket
            SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(a,
                                                                                    start=27)  # CHLO from the CHLO tag, which starts at offset 26 (22 header + frame type + stream id + offset)
            SessionInstance.get_instance().chlo += body[4:]

            # dhke.generate_keys(bytes.fromhex(previous_session.public_value), False)
            # ciphertext = CryptoManager.encrypt(bytes.fromhex(SessionInstance.get_instance().chlo), 1)
            #
            a.setfieldval('Message Authentication Hash', string_to_ascii(message_authentication_hash))
            #
            print("Send full CHLO from existing connection")
            #
            p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(
                load=string_to_ascii(body))
            # # Maybe we cannot assume that is just a version negotiation packet?
            self.sniffer.add_observer(self)
            send(p)
            self.wait_for_signal_or_expiration()

            self.processed = False
            self.sniffer.remove_observer(self)
        except Exception:
            # table is not found probably
            print("Table not found")
            self.learner.respond("NOT-ZERO")

        # ans, _ = sr(p)
        # self.handle_received_encrypted_packet(ans)
        # self.send_ack_for_encrypted_message()
        # elapsed = time.time() - start
        # self.average_response_time.append(elapsed)

    def send_encrypted_request(self):
        """
        Make an AEAD GET Request to example.org
        :return:
        """
        self.logger.info("Making GET Request")

        # Generate forward secure keys if it hasn't already been done.
        current_app_key = SessionInstance.get_instance().app_keys
        if current_app_key['type'] != "FORWARD" or current_app_key['mah'] != SessionInstance.get_instance().last_received_shlo:
            key = dhke.generate_keys(SessionInstance.get_instance().peer_public_value, True, self.logger)
            SessionInstance.get_instance().app_keys['type'] = "FORWARD"
            SessionInstance.get_instance().app_keys['mah'] = SessionInstance.get_instance().last_received_shlo
            SessionInstance.get_instance().app_keys['key'] = key

        get_request = "800300002501250000000500000000FF418FF1E3C2E5F23A6BA0AB9EC9AE38110782848750839BD9AB7A85ED6988B4C7"
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        ciphertext = CryptoManager.encrypt(bytes.fromhex(get_request), packet_number, SessionInstance.get_instance(), self.logger)

        # Send it to the server
        a = AEADRequestPacket()
        a.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        a.setfieldval("Public Flags", 0x18)
        a.setfieldval('Packet Number', packet_number)
        a.setfieldval("Message Authentication Hash", string_to_ascii(ciphertext[0:24]))

        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=6121, sport=61250) / a / Raw(
            load=string_to_ascii(ciphertext[24:]))
        self.sniffer.add_observer(self)
        send(p)
        self.wait_for_signal_or_expiration()
        self.processed = False
        self.sniffer.remove_observer(self)

    def stop_sniffer(self):
        self.sniffer.stop_sniffing()

    def send(self, command, deterministic_repeat=False):
        self.logger.info(command)
        self.current_event = command
        if not deterministic_repeat:
            self.run_events.append(command)
        try:
            if isinstance(command, ResetEvent):
                self.logger.info("Resetting received")
                self.send_chlo(True)
            if isinstance(command, SendInitialCHLOEvent):
                self.logger.info("Sending CHLO")
                self.send_chlo(False)
            elif isinstance(command, SendGETRequestEvent):
                self.logger.info("Sending GET")
                self.send_encrypted_request()
            elif isinstance(command, CloseConnectionEvent):
                self.logger.info("Closing connection")
                self.close_connection()
            elif isinstance(command, SendFullCHLOEvent):
                self.logger.info("Sending Full CHLO")
                self.send_full_chlo()
            elif isinstance(command, ZeroRTTCHLOEvent):
                self.logger.info("Sending Zero RTT CHLO")
                self.send_full_chlo_to_existing_connection()
            else:
                self.logger.info("Unknown command {}".format(command))
        except Exception as err:
            self.logger.exception(err)

    def update(self, event, result):
        try:
            self.logger.info("Scapy Received result {}".format(result))
            self.result = result
            self.processed = True
        except Exception as err:
            self.logger.error(err)


s = Scapy()

# try:
# operations = [(s.send_chlo, False), (s.send_full_chlo, True), (s.send_full_chlo_to_existing_connection, True), (s.send_encrypted_request, True), (s.close_connection, True), (s.reset, False)]
# print("Starting now {}".format(time.time()))
# for i in range(2):
#     random.shuffle(operations)
#     for operation, encrypted in operations:
#         print("PERFORMING OPERATION {}".format(operation))
#         operation()
#         print("FINISHED OPERATION {}".format(operation))
#         time.sleep(2)
# print("Done?!")
# for i in tqdm(range(2)):
# s.logger.info(">>>>>>>>>>>> Starting with round {}".format(i))
s.logger.info("Resetting")
# s.send(ResetEvent())
s.send(SendInitialCHLOEvent())
s.send(SendFullCHLOEvent())
# s.send(SendGETRequestEvent())
# s.send(CloseConnectionEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(SendGETRequestEvent())

#     s.logger.info("<<<<<<<<<<<<< Finished with round {}".format(i))

# print("Currently at {}".format(i+1))
# print("Median response time {} \nAverage response time {}".format(median(s.response_times), mean(s.response_times)))
# s.stop_sniffer()
# except Exception:
#     print("!!!!!!!!!!!!!!!!!!!!!!!!ERROR!!!!!!! {}".format())
# print("Mean time {}".format(median(s.average_response_time)))
# 324

# print("Starting public reset test")
# s.reset()
# for i in range(5):
#     s.send_encrypted_request()
