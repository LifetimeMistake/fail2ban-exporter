import socket
import pickle
import re
from typing import Optional, Self
from fail2ban_exporter.protocol import PROTO_CLOSE_MSG, PROTO_END_MSG, F2BRequest, F2BResponse

SOCKET_PATTERN = re.compile(r"^(tcp|unix)://(.*)")
SOCKET_CHUNK_SIZE = 4096

def convert_types(x):
    if isinstance(x, (str, bool, int, float, list, dict, set)):
        return x
    else:
        return str(x)

class F2BSocket:
    def __init__(self, endpoint: str, net_chunk_size: Optional[int] = None) -> Self:
        endpoint_match = SOCKET_PATTERN.match(endpoint)
        if not endpoint_match or len(endpoint_match.groups()) != 2:
            raise ValueError("Invalid endpoint format. Specify either tcp:// or unix:// as the protocol along with the socket address")
        
        protocol, address = endpoint_match.groups()
        match protocol:
            case "tcp":
                socket_type = socket.AddressFamily.AF_INET
            case "unix":
                socket_type = socket.AddressFamily.AF_UNIX
            case e:
                raise ValueError(f"Unsupported protocol {e}://")
            
        self._socket = socket.socket(socket_type, socket.SocketKind.SOCK_STREAM)
        self._socket.connect(address)
        self._chunk_size = net_chunk_size or SOCKET_CHUNK_SIZE
        
    def __serialize_req(self, message: F2BRequest) -> bytes:
        buffer = list(map(convert_types, message.to_obj()))
        return pickle.dumps(buffer, pickle.HIGHEST_PROTOCOL) + PROTO_END_MSG

    def __deserialize_res(self, data: bytes) -> F2BResponse:
        data = data[:data.rfind(PROTO_END_MSG)]
        result = list(pickle.loads(data))
        status_code = result[0]
        arg = None
        
        if len(result) == 2:
            arg = result[1]
        elif len(result) > 2:
            arg = result[1:]
            
        return F2BResponse(status_code, arg)
        
    def read(self) -> F2BResponse:
        data = b''
        while data.rfind(PROTO_END_MSG, -32) == -1:
            chunk = self._socket.recv(self._chunk_size)
            if not len(chunk):
                raise socket.error(104, 'Connection reset by peer')
            
            data += chunk
            
        return self.__deserialize_res(data)
    
    def write(self, data: F2BRequest):
        buffer = self.__serialize_req(data)
        self._socket.sendall(buffer)
    
    def write_read(self, data: F2BRequest) -> F2BResponse:
        self.write(data)
        return self.read()
    
    def close(self):
        if not self._socket:
            return
        
        self._socket.sendall(PROTO_CLOSE_MSG + PROTO_END_MSG)
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._socket = None