class SessionInstance:
    __instance = None
    server_config_id = ""
    source_address_token = ""
    public_value = None # object
    public_values_bytes = ""
    private_value = None
    chlo = ""
    scfg = ""
    cert = "308203b43082029ca003020102020101300d06092a864886f70d01010b0500301e311c301a06035504030c13515549432053657276657220526f6f74204341301e170d3138303332323134323231325a170d3139303332323134323231325a3064310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731143012060355040a0c0b51554943205365727665723112301006035504030c093132372e302e302e3130820122300d06092a864886f70d01010105000382010f003082010a0282010100c736b59daa3946856ad4c435600872cc1bda9d080d903d26c9cdcc640ceac3d0149df3de7164d63ae6cc0acefe478927a618f801bb3491904f1bddaa117e04889ed569c4f91b25ffea519e44d52dd5adc2e3c82219c69920cdabac9614b5e050224d4bdd76a8a5dfa38ded84e3bb3be440891f44f9e8b2eed6508a66d5b257c16709832f78d23371c3baca1d77fbc9b3226be2064b67b200fdb5ddc49995b13a3ae889812ed784203a5d11d72fdabbea42d9a658f6ed7799ed114dd833196ff1e52dd89191f0e462e957f4d088a4be5848a511be5712f36bd348ab5fe30c7342112b9ea70da9139ba4a80a8cf5f9e380255521a2b08bab5d2e8bb262bcf671fd0203010001a381b63081b3300c0603551d130101ff04023000301d0603551d0e041604142b02b2222d9ef7099633496d64cac59b3aff99f7301f0603551d23041830168014259334b660242a4a3e5b1bf95bfed3c3e0d70c4c301d0603551d250416301406082b0601050507030106082b0601050507030230440603551d11043d303b820f7777772e6578616d706c652e6f726782106d61696c2e6578616d706c652e6f726782106d61696c2e6578616d706c652e636f6d87047f000001300d06092a864886f70d01010b05000382010100436ccdd416efc4eda50796f61d0100187aca65eeb04f2cd84191c92d69b8b6e2f3187001e628a045505db576e978eae31b625d51d62863a1ed783b22639553b6213c476e67fb5fea20522fd7302e32124c04eaf5966740d5d9e145ee6a5b16f8f0c5ba0ae0de2edf75a1a653547fcfcf7d5d376d49efa87979fd06d969666c447f6676db9d4a0f9158e47eb88e3da13fbf3ad579863dc2963bed437806ec78ec0c3f1807f40f4984abc00ce2b747226579df9b3af66e03f1c4b9095bd624d38e0641fd1fe728a99000f7622755179b0b7cac6de25a4e293b663584334303294f6655aea4c181c2a07283515b9b87a4adeacae67982eb681f4da51574d74f27bc"
    server_nonce = "efc36b712c31d0adff9aa9f11cadc41ecc82eaa6a77edbb50539a6e614fb969da8b0d74d1a0a1026850e21412b116f9c21bcb7db"
    keys = {}
    peer_public_value = ""
    div_nonce = ""
    message_authentication_hash = ""
    associated_data = ""
    packet_number = ""
    largest_observed_packet_number = -1
    shlo_received = False

    @staticmethod
    def get_instance():
        if SessionInstance.__instance is None:
            return SessionInstance()
        else:
            return SessionInstance.__instance

    def __init__(self):
        if SessionInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.server_config_id = "-1"
            self.source_address_token = "-1"
            SessionInstance.__instance = self
