import peewee

from caching.SessionModel import SessionModel


class CacheInstance:
    """
    """
    __instance = None
    __db = None

    @staticmethod
    def get_instance():
        if CacheInstance.__instance is None:
            return CacheInstance()
        else:
            return CacheInstance.__instance

    def __init__(self):
        if CacheInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.__db = peewee.SqliteDatabase('quic_scapy.db')
            self.__db.connect()
            self.__db.drop_tables([SessionModel])
            self.__db.create_tables([SessionModel])

    def add_session_model(self, model: SessionModel):
        model.save()

    def remove_session_model(self):
        self.__db.drop_tables([SessionModel])
        self.__db.create_tables([SessionModel])

    def retrieve_current_session(self):
        return SessionModel.select()
