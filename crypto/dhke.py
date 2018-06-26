import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from donna25519 import PrivateKey, PublicKey

from caching.SessionModel import SessionModel
from util.SessionInstance import SessionInstance


class dhke:

    @staticmethod
    def set_up_my_keys():
        """
        Sets up my part for the DHKE
        :return:
        """
        private_key = PrivateKey(secret=bytes.fromhex("78E0DACE61981ECEC3F7E164AC29407C7EE0AB515AB3F9B51C3E8B58050EE646"))
        my_public_key = PublicKey(bytes.fromhex("96D49F2CE98F31F053DCB6DFE729669385E5FD99D5AA36615E1A9AD57C1B090C"))
        # private_key = PrivateKey()
        # my_public_key = PublicKey(os.urandom(32))
        SessionInstance.get_instance().public_value = my_public_key
        SessionInstance.get_instance().public_values_bytes = my_public_key.public.hex()
        # print("My public key {}".format(SessionInstance.get_instance().public_values_bytes))
        SessionInstance.get_instance().private_value = private_key

    @staticmethod
    def generate_keys(peer_public_value: bytes, forward_secure=False, logger=None):
        """
        Method that implements Diffie Hellman with Curve25519
        Receives the public value and chooses a secret value such that it is able
        to compute the shared session key ( * In this application, the output of DHKE is used
        with the salt as input for the HKDF).
        :param forward_secure:
        :param peer_public_value as bytes
        :return:
        """
        # 1. Load my key
        private_key = SessionInstance.get_instance().private_value

        # 2. compute the shared secret
        if len(peer_public_value) != 32:
            raise Exception("Invalid length of peer public value, should be 32 bytes received {} bytes".format(len(peer_public_value)))

        shared_key = private_key.do_exchange(PublicKey(peer_public_value))

        # 3. Apply the kdf
        info = dhke.generate_info(forward_secure)
        salt = bytes.fromhex("5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830") # Fixed client nonce
        # print("Forward secure? {}".format(forward_secure))
        # print("Zero rtt mode? {}".format(SessionInstance.get_instance().zero_rtt))
        # print("Using dynamic nonce? {}".format(SessionInstance.get_instance().zero_rtt or forward_secure))
        if forward_secure or SessionInstance.get_instance().zero_rtt:
            salt += bytes.fromhex(SessionInstance.get_instance().server_nonce)  # Appended with dynamic server nonce
            # print("Received server nonce {}".format(SessionInstance.get_instance().server_nonce))
        else:
            salt += bytes.fromhex("e4d458e2594b930f6d4f77711215adf9ebe99096c479dbf765f41d28646c4b87a0ec735e63cc4f19b9207d369e36968b2b2071ed") # Is it fixed?

        # print("Connection ID")
        # print(SessionInstance.get_instance().connection_id)
        #
        # print(">>>> My Salt <<<<")
        # print(salt.hex())
        #
        # print(">>>> Shared Key <<<<")
        # print(shared_key.hex())
        #
        # print(">>>> Info <<<<")
        # print(info.hex())

        logger.info("Shared key {}".format(shared_key.hex()))

        derived_shared_key = dhke.perform_hkdf(salt, shared_key, info, forward_secure)

        logger.info("Derived shared key {}".format({k: v.hex() for k, v in derived_shared_key.items()}))

        SessionInstance.get_instance().keys = derived_shared_key
        return derived_shared_key

    @staticmethod
    def perform_hkdf(salt, shared_key, info, forward_secure=False):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=40,  # 2 * keyLen (=16) + 2 * 4
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_key)
        # print("Derived shared key for AES: ")

        keys = {
            'key1': derived_key[:16],   # my key
            'key2': derived_key[16:32], # other key
            'iv1': derived_key[32:32+4],# my iv
            'iv2': derived_key[32+4:]   # other iv
        }

        # if it is not forward secure we need to diversify the keys
        if not forward_secure:
            try:
                diversified = dhke.diversify(keys['key2'], keys['iv2'], bytes.fromhex(SessionInstance.get_instance().div_nonce))
                keys['key2'] = diversified['diversified_key']
                keys['iv2'] = diversified['diversified_iv']
            except ValueError:
                print("Error in div nonce {}".format(SessionInstance.get_instance().div_nonce))

        return keys

    @staticmethod
    def diversify(key: bytes, iv: bytes, div_nonce: bytes):
        secret = key + iv

        diversified_key = HKDF(
            algorithm=hashes.SHA256(),
            length=20,  # 2 * keyLen (=16) + 2 * 4
            salt=div_nonce,
            info=bytes("QUIC key diversification", encoding='utf-8'),
            backend=default_backend()
        ).derive(secret)

        return {
            'diversified_key': diversified_key[:16],
            'diversified_iv': diversified_key[16:]
        }

    @staticmethod
    def print_like_go(info):
        info_as_string = "".join(map(chr, info))
        info_quic_style = [ord(c) for c in info_as_string]
        # print(info_quic_style)
        return info_quic_style

    @staticmethod
    def generate_info(forward_secure=False):
        info = b""
        # Fixed label
        if forward_secure:
            info += "QUIC forward secure key expansion".encode('utf-8')
        else:
            info += "QUIC key expansion".encode('utf-8')
        info += b"\x00"
        try:
            info += bytes.fromhex(SessionInstance.get_instance().connection_id)
        except ValueError:
            print("Error in connection id? {}".format(SessionInstance.get_instance().connection_id))
            return

        info += bytes.fromhex(SessionInstance.get_instance().chlo)

        info += bytes.fromhex(SessionInstance.get_instance().scfg)

        info += bytes.fromhex(SessionInstance.get_instance().cert)

        return info

    @staticmethod
    def init_golang_byte_array_from_string(input):
        input = input.replace("[", "{")
        input = input.replace("]", "}")
        input = input.replace(" ", ", ")
        # print(input)

    @staticmethod
    def compare_infos(own_info, quic_info):
        # Transform quic string to array
        quic_info_as_array = quic_info.split(" ")
        # print(quic_info_as_array)

        # print("Length of my info {}, Lenght of QUIC info {}".format(len(own_info), len(quic_info_as_array)))
        # print("Lengths are equal? {}".format(len(own_info) == len(quic_info_as_array)))

        equal = True
        for own_idx, own_char in enumerate(own_info):
            for quic_idx, quic_char in enumerate(quic_info_as_array):
                if own_idx == quic_idx:
                    if not str(own_char) == quic_char:
                        # print("At my array at place {} at I have {} but QUIC has {} at place {}".format(own_idx, own_char, quic_char, quic_idx))
                        equal = False
                        break
        # print(equal)

    @staticmethod
    def quic_go_byte_array_print_to_python_array(input):
        """
        Converts a printed byte array from GoLang to a Python byte array
        :param input:
        :return:
        """
        input = input.replace("[", "")
        input = input.replace("]", "")
        output = input.split(" ")
        output = ["%02x" % int(x) for x in output]
        # print("".join(output))
        return output