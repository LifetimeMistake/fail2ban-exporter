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