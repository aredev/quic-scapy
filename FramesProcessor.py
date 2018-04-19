from Processors.AckProcessor import AckProcessor

from Processors.BlockedProcessor import BlockedProcessor
from Processors.CongestionFeedbackProcessor import CongestionFeedbackProcessor
from Processors.ConnectionCloseProcessor import ConnectionCloseProcessor
from Processors.GoAwayProcessor import GoAwayProcessor
from Processors.PaddingProcessor import PaddingProcessor
from Processors.PingProcessor import PingProcessor
from Processors.RSTStreamProcessor import RSTStreamProcessor
from Processors.StopWaitingProcessor import StopWaitingProcessor
from Processors.StreamProcessor import StreamProcessor
from Processors.UnknownProcessor import UnknownProcessor
from Processors.WindowsUpdateProcessor import WindowUpdateProcessor


class FramesProcessor:
    """
    This class is responsible for processing all the streams in a body
    """

    packet_body = None

    def __init__(self, packet_body) -> None:
        super().__init__()
        self.packet_body = packet_body

    def process(self):

        print(self.packet_body)

        processors = [
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
                'processor': StreamProcessor(),
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
