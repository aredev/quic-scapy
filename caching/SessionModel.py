from peewee import Model, SqliteDatabase, TextField

db = SqliteDatabase('quic_scapy.db')


class BaseModel(Model):
    class Meta:
        database = db


class SessionModel(BaseModel):
    source_address_token = TextField()
    server_nonce = TextField()
    server_config_id = TextField()
    public_value = TextField()
