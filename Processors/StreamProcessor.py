import json

from Processors.ProcessedFramesInstance import ProcessedFramesInstance
from Processors.Processor import Processor
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
from util.SessionInstance import SessionInstance
from util.processor_hex_number_to_int import processor_hex_to_int


class StreamProcessor(Processor):
    packet_body = None
    data_length_present = False
    data_length = None  # 4 bytes
    offset = None  # 0, 16, 24, 32, 40, 48, 56, 64 bits
    offset_length = 0
    stream_id = None  # 8, 16, 24, 32 bits
    stream_length = 0

    reader = 0  # Index for the reader

    plaintext = ""
    first_byte_as_bits = None

    def my_frame(self):
        self.first_byte_as_bits = bin(int(self.packet_body[self.reader], base=16))[2:].zfill(8)
        return self.first_byte_as_bits[0] == "1"

    def process(self):
        """
        Assumption, the stream frame is last. FIXME
        :return:
        """
        ciphertext = self.packet_body[self.reader:]
        self.reader += len(ciphertext)

        print(len(ciphertext))

        # Nonce is iv[0:4] || packetnumber as long (8 bytes)

        # associated data, again is from the public bytes until (inclusive) packet number. 0:42
        associated_data = SessionInstance.get_instance().associated_data
        packet_number_byte = SessionInstance.get_instance().packet_number
        packet_number = int(packet_number_byte).to_bytes(8, byteorder='little')
        nonce = SessionInstance.get_instance().keys['iv2'][0:4] + packet_number

        # The ciphertext starts from the Message Authentication Hash and continues until the end of this stream
        # Containing everything it meets along the way.
        message_authentication_hash = SessionInstance.get_instance().message_authentication_hash
        ciphertext = "".join(ciphertext)
        complete_ciphertext = message_authentication_hash
        complete_ciphertext += self.processor.get_processed_bytes()
        complete_ciphertext += bytes.fromhex(ciphertext)

        print("ProcessedFrames thus far {}".format(self.processor.get_processed_bytes()))

        request_data = {
            'mode': 'decryption',
            'input': complete_ciphertext.hex(),
            'additionalData': associated_data,
            'nonce': nonce.hex(),
            'key': SessionInstance.get_instance().keys['key2'].hex()    # other key, used for decryption,.
        }

        print(request_data)

        response = ConnectionInstance.get_instance().send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(request_data).encode('utf-8'), True)
        if response['status'] == 'success':
            shlo_packet = response['data']
            print(response)
            print("Todo process the packet")

    def result(self):
        """
        Because everything is captured as ciphertext, there isn't anything left.
        :return:
        """
        return []
