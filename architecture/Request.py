from abc import ABC

from architecture.Response import Response


class Request(ABC):
    """
    Generic Request Class
    """

    __response = None

    def get_payload(self) -> bytes:
        """
        Returns the payload of a request
        :return:
        """

    def expects_response_type(self) -> Response:
        pass

    def is_correct_response(self, response: bytes) -> bool:
        pass