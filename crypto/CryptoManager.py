import json

from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from util.SessionInstance import SessionInstance


class CryptoManager:

    @staticmethod
    def encrypt(msg: bytes, packet_number: int, instance):
        """
        Encrypts the message
        :param instance:
        :param packet_number:
        :param msg:
        :return:
        """
        keys = instance.keys
        # keys = SessionInstance.get_instance().keys
        print("The keys which are used {}".format(keys))

        next_packet_number_byte = packet_number.to_bytes(8, byteorder='little')
        next_packet_number_nonce = packet_number.to_bytes(2, byteorder='big')
        # SessionInstance.get_instance().packet_number = packet_number+1

        print("Next packet number will be {}".format(next_packet_number_nonce.hex()))

        print(SessionInstance.get_instance().connection_id)

        request = {
            'mode': 'encryption',
            'input': msg.hex(),
            'key': keys['key1'].hex(),  # For encryption, we use my key
            'additionalData': "18" + instance.connection_id + next_packet_number_byte.hex()[:4],  # Fixed public flags 18 || connection Id || packet number
            'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
        }

        print(request)
        ciphertext = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE,
                                                                    json.dumps(request).encode('utf-8'), True)
        print("Received {}".format(ciphertext))
        return ciphertext['data']
