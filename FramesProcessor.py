import json

from Processors.AckProcessor import AckProcessor

from Processors.BlockedProcessor import BlockedProcessor
from Processors.CongestionFeedbackProcessor import CongestionFeedbackProcessor
from Processors.ConnectionCloseProcessor import ConnectionCloseProcessor
from Processors.GoAwayProcessor import GoAwayProcessor
from Processors.PaddingProcessor import PaddingProcessor
from Processors.PingProcessor import PingProcessor
from Processors.ProcessedFramesInstance import ProcessedFramesInstance
from Processors.RSTStreamProcessor import RSTStreamProcessor
from Processors.StopWaitingProcessor import StopWaitingProcessor
from Processors.StreamProcessor import StreamProcessor
from Processors.UnknownProcessor import UnknownProcessor
from Processors.WindowsUpdateProcessor import WindowUpdateProcessor
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
from util.SessionInstance import SessionInstance
from util.split_at_every_n import split_at_nth_char


class FramesProcessor:
    """
    This class is responsible for processing all the streams in a body
    """

    packet_body = None
    processedFramesInstance = None

    def __init__(self, packet_body) -> None:
        super().__init__()
        self.packet_body = packet_body

    def process(self):

        self.processedFramesInstance = ProcessedFramesInstance.get_instance()
        self.processedFramesInstance.reset_processed_bytes()

        # Response is encrypted so we need to decrypt it
        associated_data = SessionInstance.get_instance().associated_data
        packet_number = SessionInstance.get_instance().packet_number.to_bytes(8, byteorder='little')
        nonce = SessionInstance.get_instance().keys['iv2'][0:4] + packet_number

        # The ciphertext starts from the Message Authentication Hash and continues until the end of this stream
        # Containing everything it meets along the way.
        message_authentication_hash = SessionInstance.get_instance().message_authentication_hash
        ciphertext = "".join(self.packet_body)
        complete_ciphertext = message_authentication_hash
        complete_ciphertext += self.processedFramesInstance.get_processed_bytes().hex()
        complete_ciphertext += ciphertext

        print("ProcessedFrames thus far {}".format(self.processedFramesInstance.get_processed_bytes()))

        request_data = {
            'mode': 'decryption',
            'input': complete_ciphertext,
            'additionalData': associated_data,
            'nonce': nonce.hex(),
            'key': SessionInstance.get_instance().keys['key2'].hex()  # other key, used for decryption,.
        }

        print(request_data)

        response = ConnectionInstance.get_instance().send_message(ConnectionEndpoint.CRYPTO_ORACLE,
                                                                  json.dumps(request_data).encode('utf-8'), True)

        print("Response after decryption {}".format(response['data']))
        self.packet_body = split_at_nth_char(response['data'])

        processors = [
            {
                'processor': StreamProcessor(),
                'processes': 0
            },
            {
                'processor': AckProcessor(),
                'processes': 0
            },
            {
                'processor': BlockedProcessor(),
                'processes': 0
            },
            {
                'processor': CongestionFeedbackProcessor(),
                'processes': 0
            },
            {
                'processor': ConnectionCloseProcessor(),
                'processes': 0
            },
            {
                'processor': GoAwayProcessor(),
                'processes': 0
            },
            {
                'processor': PaddingProcessor(),
                'processes': 0
            },
            {
                'processor': PingProcessor(),
                'processes': 0
            },
            {
                'processor': RSTStreamProcessor(),
                'processes': 0
            },
            {
                'processor': StopWaitingProcessor(),
                'processes': 0
            },
            {
                'processor': WindowUpdateProcessor(),
                'processes': 0
            },
            {
                'processor': UnknownProcessor(),
                'processes': -999999
            }
        ]

        while len(self.packet_body) > 0:
            # As long as we need to process the packet body
            for processor in processors:
                processor['processor'].receive(self.packet_body)
                if processor['processor'].my_frame():
                    print("Processed by {}".format(processor))
                    processor['processor'].process()
                    self.packet_body = processor['processor'].result()
                    processor['processes'] += 1
                    break
