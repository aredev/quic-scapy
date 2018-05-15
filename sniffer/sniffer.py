from threading import Thread
from typing import Optional, Callable, Iterable, Mapping, Any

from scapy.sendrecv import sniff


class Sniffer(Thread):

    __observers = []
    __stop_sniffing = False

    def run(self) -> None:
        self.__stop_sniffing = False
        nr_packets = sniff(prn=self.inform_observer, filter="udp and dst port 61250 and src port 6121", store=1, stop_filter=self.do_i_need_to_stop)
        print("Sniffing stopped with {}".format(nr_packets))

    def add_observer(self, observer):
        self.__observers.append(observer)

    def inform_observer(self, packet):
        for observer in self.__observers:
            print("Informed observer {}".format(observer))
            observer.packet_update(packet)

    def do_i_need_to_stop(self, packet):
        return self.__stop_sniffing

    def remove_observer(self, observer):
        self.__observers.remove(observer)

    def stop_sniffing(self):
        self.__stop_sniffing = True