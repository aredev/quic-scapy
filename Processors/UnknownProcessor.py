from Processors.Processor import Processor


class UnknownProcessor(Processor):
    """
    As a last resort for unknown frames this will just except everything and continue.
    Only works if there is the unknown frame has just one byte composed of the frame type.
    """
    def my_frame(self):
        return True

    def process(self):
        self.reader += 1
