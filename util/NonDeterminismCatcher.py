import logging

from peewee import SqliteDatabase

from caching.SessionModel import LearningRunModel, NonDeterministicResponseModel


class NonDeterminismCatcher:

    __db = None
    __logging = None

    def __init__(self, logger) -> None:
        self.__db = SqliteDatabase('non_determinism_quic.db')
        self.__db.connect()
        self.__db.drop_tables([LearningRunModel, NonDeterministicResponseModel])
        self.__db.create_tables([LearningRunModel, NonDeterministicResponseModel])
        self.__logging = logger
        logger = logging.getLogger('peewee')
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)

    def add_run(self, q, res):
        # Check if there is already a record with this query
        try:
            if not res:
                res = "---"
            previous_run = LearningRunModel.get(LearningRunModel.run == q)
            self.__logging.info("Received query {}".format(q))
            if not previous_run.result == res:
                self.__logging.info("Not deterministic with {}".format(previous_run.result))
                NonDeterministicResponseModel(
                    run=q,
                    result=res
                ).save()
        except LearningRunModel.DoesNotExist:
            self.__logging.info("New run inserted.")
            LearningRunModel(
                run=q,
                result=res
            ).save()
