from Processors.ProcessedFramesInstance import ProcessedFramesInstance


class Processor:
    """
    Abstract class for the processors
    The goal is that each processor receives a string XXXXXXXXXXXXXXX || YYYYYYYYYYYYYYY || ZZZZZZZZZZZZZZZZZ
    And the XProcessor (processor that can process messages from frame type X) do their job and remove everything from X
    Such that YProcessor can continue and process and remove everything from y
    Followed by the ZProcessor, such that it can remove everything from z.
    This results that everything is processed.
    """

    packet_body = None
    reader = 0
    processor = None

    def set_processor(self, processor):
        self.processor = processor

    def receive(self, packet_body):
        """
        Receives the packet body and just stores it
        :param packet_body:
        :return:
        """
        self.packet_body = packet_body
        self.reader = 0

    def my_frame(self):
        """
        Should this processor process this frame
        :return:
        """
        raise NotImplementedError("Oops, you've forgotten to implement this :)")

    def process(self):
        """
        Does the actual processing of the packet body.
        If there is a need for preprocessing, the processor should handle this by itself.
        :return:
        """
        raise NotImplementedError("Oops, you've forgotten to implement this :)")

    def result(self):
        """
        Returns a result of the processing
        :return:
        """
        return self.packet_body[self.reader:]

    def store_processed_bytes(self):
        """
        Stores the processed bytes to the instance class
        :return:
        """
        self.processor.append_bytes(bytes.fromhex("".join(self.packet_body[0:self.reader])))
