from Processors.Processor import Processor


class PaddingProcessor(Processor):
    def my_frame(self):
        return self.packet_body[self.reader] == "00"

    def process(self):
        pass

    def result(self):
        return []
