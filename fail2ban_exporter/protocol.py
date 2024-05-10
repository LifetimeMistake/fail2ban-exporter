from abc import ABC
from typing import Any, Self

PROTO_END_MSG = b"<F2B_END_COMMAND>"
PROTO_CLOSE_MSG = b"<F2B_CLOSE_COMMAND>"


class F2BMessage(ABC):
    def to_obj(self) -> list[Any]:
        pass


class F2BRequest(F2BMessage):
    def __init__(self, command: list[Any]) -> Self:
        self.command = command

    def to_obj(self) -> list[Any]:
        return self.command


class F2BResponse(F2BMessage):
    def __init__(self, status_code: int, data: Any) -> Self:
        self.status_code = status_code
        self.data = data

    @property
    def is_success(self):
        return self.status_code == 0

    @property
    def has_data(self):
        return True if self.data else False

    def to_obj(self) -> list[Any]:
        return [self.status_code, *self.data]


class F2BJail:
    def __init__(
        self,
        currently_failed: int,
        total_failed: int,
        currently_banned: int,
        total_banned: int,
        filter_file_list: list[str],
        banned_ips: list[str],
    ) -> Self:
        self.currently_failed = currently_failed
        self.total_failed = total_failed
        self.currently_banned = currently_banned
        self.total_banned = total_banned
        self.filter_file_list = filter_file_list
        self.banned_ips = banned_ips