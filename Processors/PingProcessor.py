from Processors.Processor import Processor


class PingProcessor(Processor):
    def my_frame(self):
        return self.packet_body[self.reader] == "0x07"

    def process(self):
        """
        Only has the frame type
        :return:
        """
        self.reader += 1
