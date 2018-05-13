from threading import Thread

from scapy.sendrecv import sniff


class Sniffer(Thread):

    __observers = []

    def run(self) -> None:
        sniff(prn=self.inform_observer, filter="udp and dst port 61250 and src port 6121", store=1)

    def add_observer(self, observer):
        self.__observers.append(observer)

    def inform_observer(self, packet):
        for observer in self.__observers:
            print("Informed observer {}".format(observer))
            observer.packet_update(packet)

    def remove_observer(self, observer):
        self.__observers.remove(observer)
