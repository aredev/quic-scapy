import json
import socket
from enum import Enum


class ConnectionInstance:
    __instance = None
    socket = None

    @staticmethod
    def get_instance():
        if ConnectionInstance.__instance is None:
            return ConnectionInstance()
        else:
            return ConnectionInstance.__instance

    def __init__(self):
        if ConnectionInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(("localhost", 3030))
            ConnectionInstance.__instance = self

    def send_message(self, endpoint, msg: bytes, expect_answer=False):
        if endpoint == ConnectionEndpoint.CRYPTO_ORACLE:
            self.socket.send(msg)
            if expect_answer:
                data = self.socket.recv(555555)
                decoded_data = data.decode('utf-8')
                return json.loads(decoded_data)
        else:
            raise NotImplementedError("Currently only Crypto Oracle")


class ConnectionEndpoint(Enum):
    CRYPTO_ORACLE = 1
    LEARNER = 2
