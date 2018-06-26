import json
from json import JSONDecodeError

from Processors.AckProcessor import AckProcessor

from Processors.BlockedProcessor import BlockedProcessor
from Processors.CongestionFeedbackProcessor import CongestionFeedbackProcessor
from Processors.ConnectionCloseProcessor import ConnectionCloseProcessor
from Processors.GoAwayProcessor import GoAwayProcessor
from Processors.PaddingProcessor import PaddingProcessor
from Processors.PingProcessor import PingProcessor
from Processors.ProcessedFramesInstance import ProcessedFramesInstance
from Processors.RSTStreamProcessor import RSTStreamProcessor
from Processors.SHLOPacketProcessor import SHLOPacketProcessor
from Processors.StopWaitingProcessor import StopWaitingProcessor
from Processors.StreamProcessor import StreamProcessor
from Processors.UnknownProcessor import UnknownProcessor
from Processors.WindowsUpdateProcessor import WindowUpdateProcessor
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from util.SessionInstance import SessionInstance
from util.index_of_string_finder import find_all_indexes_of_substring_in_string
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

    def process(self, is_encrypted=True, logger=None):

        self.processedFramesInstance = ProcessedFramesInstance.get_instance()
        self.processedFramesInstance.reset_processed_bytes()

        if is_encrypted:
            # Response is encrypted so we need to decrypt it
            associated_data = SessionInstance.get_instance().associated_data
            packet_number = int(SessionInstance.get_instance().packet_number, 16).to_bytes(8, byteorder='little')
            nonce = SessionInstance.get_instance().keys['iv2'][0:4] + packet_number

            # The ciphertext starts from the Message Authentication Hash and continues until the end of this stream
            # Containing everything it meets along the way.
            message_authentication_hash = SessionInstance.get_instance().message_authentication_hash
            ciphertext = "".join(self.packet_body)
            complete_ciphertext = message_authentication_hash
            complete_ciphertext += self.processedFramesInstance.get_processed_bytes().hex()
            complete_ciphertext += ciphertext

            # print("ProcessedFrames thus far {}".format(self.processedFramesInstance.get_processed_bytes()))

            request_data = {
                'mode': 'decryption',
                'input': complete_ciphertext,
                'additionalData': associated_data,
                'nonce': nonce.hex(),
                'key': SessionInstance.get_instance().keys['key2'].hex()  # other key, used for decryption,.
            }

            logger.info("Requesting decryption for {}".format(request_data))

            try:
                response = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE,
                                                                      json.dumps(request_data).encode('utf-8'), True)
                # print("Response after decryption {}".format(response['data']))
                logger.info("Decrypted {}".format(response['data']))
                self.packet_body = split_at_nth_char(response['data'])
            except JSONDecodeError as err:
                self.packet_body = []

        processors = [
                    {
                        'processor': StreamProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': BlockedProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': CongestionFeedbackProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': ConnectionCloseProcessor(),
                        'result': 'closed',
                        'processes': 0
                    },
                    {
                        'processor': GoAwayProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': PaddingProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': PingProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': RSTStreamProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': StopWaitingProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': WindowUpdateProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': AckProcessor(),
                        'result': '',
                        'processes': 0
                    },
                    {
                        'processor': UnknownProcessor(),
                        'result': '',
                        'processes': -999999
                    }
                ]

        processed_by = []
        # while len(self.packet_body) > 0:
        #     # As long as we need to process the packet body
        #     for processor in processors:
        #         processor['processor'].receive(self.packet_body)
        #         if processor['processor'].my_frame():
        #             processor['processor'].process()
        #             logger.info("Processing started by {}".format(processor['processor']))
        #             self.packet_body = processor['processor'].result()
        #             print("Processed by {} with result {}".format(processor['processor'], self.packet_body))
        #             processor['processes'] += 1
        #
        #             if isinstance(processor['processor'], StreamProcessor):
        #                 print("Stream processor has status {}".format(processor['processor'].status))
        #                 processor['result'] = processor['processor'].status
        #                 logger.info("Result of stream processor {}".format(processor['result']))
        #
        #             if not processor['result'] == "":
        #                 processed_by.append(processor['result'])
        #             break
        packet_as_string = "".join(self.packet_body)
        # regexes for the SHLO part
        indexes = find_all_indexes_of_substring_in_string(packet_as_string, "a001")
        indexes += find_all_indexes_of_substring_in_string(packet_as_string, "a401")
        # regex for the HTTP part
        indexes += find_all_indexes_of_substring_in_string(packet_as_string, "c0053c")
        for index in indexes:
            processor = StreamProcessor()
            processor.receive(split_at_nth_char(packet_as_string[index:], 2))
            processor.process()
            processed_by.append(processor.status)

        # print("Finished processing ? {} ".format(processed_by))

        # logger.info("After processing {}".format(processed_by))
        if len(processed_by) > 0:
            # print("Process result {}".format(processed_by[0]))
            if processed_by.count('unknown') == len(processed_by):
                return 'unknown'
            else:
                logger.info("Complete processed by in FP {}".format(processed_by))
                p = list(filter(lambda a: a != 'unknown', processed_by))[0]
                logger.info("Returning in FramesProcessor {}".format(p))
                return p


# fp = FramesProcessor("c0053c21646f63747970652068746d6c3e0a3c68746d6c3e0a3c686561643e0a202020203c7469746c653e4578616d706c6520446f6d61696e3c2f7469746c653e0a3c2f686561643e0a0a3c626f64793e0a3c6469763e0a202020203c68313e4c6f72656d20497073756d3c2f68313e0a3c2f6469763e0a3c2f626f64793e0a3c2f68746d6c3e0a9e95d9e475bda1ab0b789ce6bdcf7a37c838711ff2ce8183")
# fp.process(False)
