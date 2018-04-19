import os

from donna25519 import PrivateKey, PublicKey


def generation_exchange_test():
    private = PrivateKey()
    public = PublicKey(public=os.urandom(32))
    shared = private.do_exchange(public)
    print(shared.hex())


def exchange_test():
    private = PrivateKey().load(bytes.fromhex("309368A4418E889426F4655235E3605DA3D9EF9F942727C76D32EBA3A5579E41"))
    public = PublicKey(bytes.fromhex("436D986682B88E668F383B8D7155B8CB30FFC739EDA65E198D471087C596B17B"))
    shared = private.do_exchange(public)
    print(shared.hex())

generation_exchange_test()
