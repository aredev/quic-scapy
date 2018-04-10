from Processors.Processor import Processor


class StopWaitingProcessor(Processor):

    def my_frame(self):
        return self.packet_body[self.reader] == "06"

    def process(self):
        self.reader += 1
