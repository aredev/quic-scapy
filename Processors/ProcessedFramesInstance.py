class ProcessedFramesInstance:
    """
    Class that holds the bytes for all the frames that have been processed.
    This is needed because the stream processor needs everything that has been processed as input to append to the
    ciphertext.
    """

    __instance = None
    processed_bytes = b""

    @staticmethod
    def get_instance():
        if ProcessedFramesInstance.__instance is None:
            return ProcessedFramesInstance()
        else:
            return ProcessedFramesInstance.__instance

    def __init__(self):
        if ProcessedFramesInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.reset_processed_bytes()

    def reset_processed_bytes(self):
        self.processed_bytes = b""

    def append_bytes(self, data: bytes):
        self.processed_bytes += data

    def get_processed_bytes(self):
        return self.processed_bytes
