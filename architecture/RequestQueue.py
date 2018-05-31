from architecture.Request import Request


class RequestsQueue:

    __queue = []
    __busy = False

    def add_to_queue(self, request: Request):
        if len(self.__queue) == 0:
            self.__busy = True
            self.send_first_request()
        else:
            self.__queue.append(request)

    def send_first_request(self):
        