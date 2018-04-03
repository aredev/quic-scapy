class SessionInstance:
    __instance = None
    server_config_id = ""

    @staticmethod
    def get_instance():
        if SessionInstance.__instance is None:
            SessionInstance()
        return SessionInstance.__instance

    def __init__(self):
        if SessionInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            SessionInstance.server_config_id = "-1"