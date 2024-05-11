from prometheus_client import Counter, start_http_server, Gauge
from fail2ban_exporter.ipapi import HostData

class Metrics:
    def __init__(self):
        self._jail_count_total = Gauge("f2b_jail_count_total", "Total amount of active jails")
        self._currently_failed = Gauge("f2b_currently_failed", "The number of IP addresses that triggered the filter since the start of Fail2Ban", labelnames=["jail"])
        self._failed_total = Gauge("f2b_failed_total", "Total number of IP addresses that triggered the filter", labelnames=["jail"])
        self._currently_banned = Gauge("f2b_currently_banned", "The number of IP addresses that were banned since the start of Fail2Ban", labelnames=["jail"])
        self._banned_total = Gauge("f2b_banned_total", "Total number of IP addresses that are banned", labelnames=["jail"])
        self._attackers = Gauge("f2b_current_attackers", "Currently known attackers", labelnames=["ip_address", "country", "region", "city", "isp", "lat", "lon", "mobile", "proxy", "hosting"])
        self._exporter_errors = Counter("f2b_exporter_errors", "The number of errors encountered since the exporter started")
        self._known_attackers = {}
        
    def start_server(self, port: int, host: str = "0.0.0.0"):
        return start_http_server(port, host)
    
    def update_jail_counts(self, jail_name: str, currently_failed: int, failed_total: int, currently_bannned: int, total_banned: int):
        self._currently_failed.labels(jail_name).set(currently_failed)
        self._failed_total.labels(jail_name).set(failed_total)
        self._currently_banned.labels(jail_name).set(currently_bannned)
        self._banned_total.labels(jail_name).set(total_banned)
        
    def add_attacker(self, attacker: HostData):
        fields = attacker.fields
        labels = [
            attacker.host,
            fields["country"],
            fields["regionName"],
            fields["city"],
            fields["isp"],
            fields["lat"],
            fields["lon"],
            fields["mobile"],
            fields["proxy"],
            fields["hosting"]
        ]
        
        old_labels = self._known_attackers.get(attacker.host)
        if old_labels:
            self._attackers.remove(old_labels)
        
        self._known_attackers[attacker.host] = labels
        self._attackers.labels(labels).set(1)
    
    def remove_attacker(self, ip_address: str) -> bool:
        labels = self._known_attackers.get(ip_address)
        if not labels:
            return False
        
        self._attackers.remove(labels)
        del self._known_attackers[ip_address]
        
    def report_error(self):
        self._exporter_errors.inc()