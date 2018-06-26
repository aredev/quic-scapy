import json

from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from util.SessionInstance import SessionInstance


class CryptoManager:

    @staticmethod
    def encrypt(msg: bytes, packet_number: int, instance, logging=None):
        """
        Encrypts the message
        :param instance:
        :param packet_number:
        :param msg:
        :return:
        """
        keys = instance.keys
        # keys = True
        # If there are no keys, just return the original message.
        if keys:
            # keys = SessionInstance.get_instance().keys
            # print("The keys which are used {}".format(keys))

            next_packet_number_byte = packet_number.to_bytes(8, byteorder='little')
            next_packet_number_nonce = packet_number.to_bytes(2, byteorder='big')

            request = {
                'mode': 'encryption',
                'input': msg.hex(),
                'key': keys['key1'].hex(),  # For encryption, we use my key
                'additionalData': "18" + instance.connection_id + next_packet_number_byte.hex()[:4],  # Fixed public flags 18 || connection Id || packet number
                'nonce': keys['iv1'].hex() + next_packet_number_nonce.hex().ljust(16, '0')
            }

            logging.info("Crypto Manager request @ {}".format(request))

            # print(request)
            ciphertext = CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE,
                                                                        json.dumps(request).encode('utf-8'), True)
            logging.info("Crypto manager result @ {}".format(ciphertext))
            return ciphertext['data']
        else:
            return msg.hex()

    @staticmethod
    def debug():
        request = {
            'mode': 'decryption',
            'input': "6ba20a407566f212b75709c60c93105b677379937e7c6ec1b9df1a06cc176a539eb5a661c8624699110a2062cd4824d2f6dc639e5410e3726368d7928a0e633d2b0e2c3fbd687f6c2619fbda78718642860fb3480ee347628e113ecc165086b92dd6e7c5a8ae4763197575f04b7de3716ed80d08a76479d5fd9969d213924be470465ba5667ec27573f658bb1cfcdd3db6fc6fb45063b8ea9874bf38d6555fe9b742a4eeddab332d5800954a18caab43688e09d768c446f4d9f39b620e5e1a98e7b2e13c56eff22c2d8cae850d80112896b584077e",
            'key': "ea36c93970077b4823f23642a69a9a05".replace(" ", ""),
            'additionalData': "086b402550648a71ae08".replace(" ", ""),
            # Fixed public flags 18 || connection Id || packet number
            'nonce': "84d86f130800000000000000"
        }

        # print(CryptoConnectionManager.send_message(ConnectionEndpoint.CRYPTO_ORACLE, json.dumps(request).encode('utf-8'), True))

# CryptoManager.debug()
