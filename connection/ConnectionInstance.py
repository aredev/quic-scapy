import _thread
import json
import socket
import threading
from enum import Enum


class ConnectionInstance:
    """
    Singleton class responsible for communication with the Crypto Oracle and receiving messages from the Learner
    """
    __instance = None
    crypto_socket = None
    learner_socket = None
    learner_connection = None

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
            # Connect with the crypto oracle
            self.crypto_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                print("Connecting with Oracle")
                ConnectionInstance.__instance = self
                print("Connected with Crypto Oracle")
            except ConnectionRefusedError:
                print("Is the Crypto Oracle enabled?")

            # _thread.start_new_thread(self.handle_learner, (self, ))

    def handle_learner(self, useless):
        # set up socket for the Learner
        self.learner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.learner_socket.bind(("192.168.1.70", 4242))
        print("Server active ... Listening on port 4242")
        self.learner_socket.listen()
        self.learner_connection, address = self.learner_socket.accept()
        print("Connected with {}".format(address))
        finished = False
        while not finished:
            data = self.learner_connection.recv(1024)
            data_as_string = data.decode('utf-8').rstrip()
            print(data_as_string)
            if data_as_string == "Close":
                print("You're done!")
                finished = True
            else:
                self.learner_connection.send("Response".encode('utf-8'))

        self.learner_connection.close()

    def send_message(self, endpoint, msg: bytes, expect_answer=False):
        # Todo: remove singleton, just make it a static method.
        if endpoint == ConnectionEndpoint.CRYPTO_ORACLE:
            print("Sending message ...")
            self.crypto_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.crypto_socket.connect(("192.168.1.70", 3030))
            self.crypto_socket.send(msg)
            if expect_answer:
                # Arbitrary big sized buffer
                print("Waiting for response...")
                data = self.crypto_socket.recv(555555)
                decoded_data = data.decode('utf-8')
                return json.loads(decoded_data)
            self.crypto_socket.close()
        else:
            raise NotImplementedError("Currently only Crypto Oracle")


class ConnectionEndpoint(Enum):
    CRYPTO_ORACLE = 1
    LEARNER = 2
