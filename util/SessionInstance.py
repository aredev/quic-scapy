class SessionInstance:
    __instance = None
    server_config_id = ""
    source_address_token = ""
    public_value = ""
    private_value = None
    chlo = ""
    scfg = ""
    cert = ""
    server_nonce = ""
    shared_key = ""

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
