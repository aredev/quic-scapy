from boofuzz import Session, Target, SocketConnection, s_initialize

session = Session(
    target=Target(connection=SocketConnection("127.0.0.1", 6021, proto='udp'))
)

s_initialize("INIT_CHLO")
