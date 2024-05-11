import logging
from typing import Optional, Self
from fail2ban_exporter.constants import F2B_SOCKET_URI
from fail2ban_exporter.protocol import F2BRequest, F2BResponse, F2BJail
from fail2ban_exporter.socket import F2BSocket

class F2BClient:
    def __init__(self, host: Optional[str] = None) -> Self:
        self._host = host or F2B_SOCKET_URI
        self._socket = None
        self.__open_socket()
        self._logger = logging.getLogger()
        
    def __open_socket(self):
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                self._logger.error("Failed to gracefully close old socket", exc_info=e)
                
        self._socket = F2BSocket(self._host)
        
    def __read(self) -> F2BResponse:
        try:
            return self._socket.read()
        except Exception as e:
            self._logger.warn("Failed to read data", exc_info=e)
            # try again
            self.__open_socket()
            return self.__read()
    
    def __write(self, data: F2BRequest):
        try:
            self._socket.write(data)
        except Exception as e:
            self._logger.warn("Failed to write data", exc_info=e)
            # try again
            self.__open_socket()
            self.__write(data)
            
    @staticmethod
    def __assert_response_ok(response: F2BResponse):
        if not response.is_success:
            if isinstance(response.data, Exception):
                raise response.data
            elif isinstance(response.data, str):
                raise RuntimeError(f"Fail2Ban server returned error: {response.data}")
            else:
                raise RuntimeError(f"Fail2Ban server returned status code {response.status_code}")
            
    def __write_read(self, data: F2BRequest) -> F2BResponse:
        self.__write(data)
        return self.__read()

    def get_jail_names(self) -> list[str]:
        response = self.__write_read(F2BRequest(["status"]))
        F2BClient.__assert_response_ok(response)
        jails = list(response.data[1][1:])
        return jails

    def get_jail_details(self, jail_name: str) -> F2BJail:
        response = self.__write_read(F2BRequest(["status", jail_name]))
        F2BClient.__assert_response_ok(response)
        filter_data, action_data = response.data[0][1], response.data[1][1]
        jail = F2BJail(
            name=jail_name,
            currently_failed=filter_data[0][1],
            total_failed=filter_data[1][1],
            filter_file_list=list(filter_data[2][1]),
            currently_banned=action_data[0][1],
            total_banned=action_data[1][1],
            banned_ips=list(action_data[2][1])
        )
        
        return jail
    
    def ban_ip(self, address: str, jail_name: str) -> bool:
        response = self.__write_read(["set", jail_name, "banip", address])
        F2BClient.__assert_response_ok(response)
        return response.data[0] == 1
    
    def unban_ip(self, address: str, jail_name: Optional[str]) -> bool:
        if jail_name is not None:
            cmd = ["set", jail_name, "unbanip", address]
        else:
            cmd = ["unban", address]
            
        response = self.__write_read(cmd)
        F2BClient.__assert_response_ok(response)
        return response.data[0] == 1