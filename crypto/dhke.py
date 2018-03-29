import binascii
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from binascii import hexlify


class dhke:

    @staticmethod
    def generate_keys():
        """
        Method that implements Diffie Hellman with Curve25519
        Receives the public value and chooses a secret value such that it is able
        to compute the shared session key ( * In this application, the output of DHKE is used
        with the salt as input for the HKDF).
        :return:
        """
        # 1. Choose a private key
        private_key = X25519PrivateKey.generate()

        # 2. get the value from the other party
        # peer_public_key_generated = X25519PrivateKey.generate().public_key()
        # print(peer_public_key_generated.public_bytes())

        peer_public_value = X25519PublicKey.from_public_bytes(b'\x29\xfd\x1f\xbf\xc3\x40\xa5\x63\x0f\xae\x3b\xe5\x4d\x28\xea\x5c\x82\xc2\x56\x01\xcf\x3e\xed\xb5\x3d\x34\x6a\xd8\x82\x2b\x64\x4a')

        # 3. compute the shared secret
        shared_key = private_key.exchange(peer_public_value)
        print(shared_key)
        return shared_key

    def wireshark_value_to_public_key_bytes(self, value):
        """
        As the wireshark bytes are a little different than the expected input for the `from_public_bytes method we need to change some of the params`
        :param value:
        :return:
        """
        # Remove all trailing zeros

        # Add \x with every byte

        # surround with b\' \'

    @staticmethod
    def hkdf_info():
        label_as_hex = b"51554943206b657920657870616e73696f6e"
        output = label_as_hex + b"00"
        guid = b""
        output += guid
        client_hello = b"0da63e2f418e429dbd51303339016e50c9906b850e0e4a933e22a001051443484c4f0f0000005041440029040000534e490038040000564552003c040000434353004c0400004d5350435004000050444d4454040000534d484c580400004943534c5c0400004354494d640400004e4f4e50840400004d4944538804000053434c538c040000435343548c040000434643579004000053464357940400002d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d7777772e6578616d706c652e6f72675130333901e8816092921ae87eed8086a2158291640000005835303901000000580200001dd1af5a0000000048b7d4568308da1ad80547983398cd5137db8fb9b9ece5eb23f27f2b12e59bf264000000010000000000f000000060000000000000000000000000000000000000000000"
        output += client_hello
        server_config = b"534346470600000041454144080000005343494418000000505542533b0000004b4558533f0000004f42495447000000455850594f0000004145534743433230ea7b535049337daa10b4bc068bf3d7c920000029fd1fbfc340a5630fae3be54d28ea5c82c25601cf3eedb53d346ad8822b644a43323535f541efd542ca6b4b86179d5b00000000"
        output += server_config

        return output

    @staticmethod
    def perform_hkdf(salt, shared_key, info):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_key)
        print("Derived shared key for AES: ")
        print(derived_key)
        return derived_key

    @staticmethod
    def generate_info():
        info = bytearray()
        # Fixed label
        label = b"QUIC forward secure key expansion"
        label_in_bytes = binascii.hexlify(label)
        info.append(label_in_bytes)
        info.append(b'00')

        info.append(bytes(14708506640392829143))

        print(info)


dhke.generate_info()
# shared_key = dhke.generate_keys()
# client_nonce = b'\x48\xb7\xd4\x56\x83\x08\xda\x1a\xd8\x05\x47\x98\x33\x98\xcd\x51\x37\xdb\x8f\xb9\xb9\xec\xe5\xeb\x23\xf2\x7f\x2b\x12\xe5\x9b\xf2'
# server_nonce = b''
# salt = client_nonce + server_nonce
# print(salt)
# info = dhke.hkdf_info()
# dhke.perform_hkdf(salt, shared_key, info)

