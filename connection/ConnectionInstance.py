import _thread
import json
import socket
import threading
from enum import Enum

from util.SessionInstance import SessionInstance


class CryptoConnectionManager:
    """
    Singleton class responsible for communication with the Crypto Oracle and receiving messages from the Learner
    """

    @staticmethod
    def send_message(endpoint, msg: bytes, expect_answer=False):
        if endpoint == ConnectionEndpoint.CRYPTO_ORACLE or True:
            print("Sending message ...")
            crypto_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            crypto_socket.connect((SessionInstance.get_instance().destination_ip, 3030))
            crypto_socket.send(msg)
            if expect_answer:
                # Arbitrary big sized buffer
                print("Waiting for response...")
                data = crypto_socket.recv(555555)
                decoded_data = data.decode('utf-8')
                return json.loads(decoded_data)
            crypto_socket.close()
        else:
            raise NotImplementedError("Currently only Crypto Oracle")


class ConnectionEndpoint(Enum):
    CRYPTO_ORACLE = 1
    LEARNER = 2
