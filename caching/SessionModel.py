import datetime

from peewee import Model, SqliteDatabase, TextField, AutoField, DateTimeField

db = SqliteDatabase('quic_scapy.db')


class BaseModel(Model):
    class Meta:
        database = db


class SessionModel(BaseModel):
    id = AutoField()
    source_address_token = TextField()
    server_nonce = TextField()
    server_config_id = TextField()
    public_value = TextField()
    connection_id = TextField()


class LearningRunModel(BaseModel):
    id = AutoField()
    run = TextField()
    result = TextField(default="---")
    created_at = DateTimeField(default=datetime.datetime.now())


class NonDeterministicResponseModel(BaseModel):
    id = AutoField()
    run = TextField()
    result = TextField(default="---")
    created_at = DateTimeField(default=datetime.datetime.now())
