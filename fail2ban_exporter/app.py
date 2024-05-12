import datetime
import logging
import os
import time

from fail2ban_exporter.client import F2BClient
from fail2ban_exporter.ipapi import IPAPI, HostData, QueryResult
from fail2ban_exporter.metrics import Metrics

ATTACKER_DATA_REFRESH_INTERVAL = int(os.getenv("ATTACKER_DATA_REFRESH_INTERVAL", 432000))
SCRAPE_INTERVAL_SECONDS = int(os.getenv("SCRAPE_INTERVAL_SECONDS", 30))
F2B_SOCKET_URI = os.getenv("F2B_SOCKET_URI")
IPAPI_USER_AGENT = os.getenv("USER_AGENT")
IPAPI_URL = os.getenv("IPAPI_URL")
IPAPI_BATCH_SIZE = os.getenv("IPAPI_BATCH_SIZE")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", 9090))

formatter = logging.Formatter('%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)
logger.addHandler(console_handler)
api = IPAPI(IPAPI_URL, IPAPI_BATCH_SIZE, IPAPI_USER_AGENT)
metrics = Metrics()
client = F2BClient(F2B_SOCKET_URI)

known_jails = {}
known_attackers = {}

def report_error():
    try:
        metrics.report_error()
    except Exception as e:
        logger.error("Failed to report error", exc_info=e)

def perform_update():
    try:
        jail_names = client.get_jail_names()
    except Exception as e:
        logger.error("Failed to get list of jails", exc_info=e)
        report_error()
        return

    for jail_name in jail_names:
        try:
            jail = client.get_jail_details(jail_name)
            known_jails[jail_name] = jail.banned_ips
            metrics.update_jail_counts(
                jail.name,
                jail.currently_failed,
                jail.total_failed,
                jail.currently_banned,
                jail.total_banned,
            )
        except Exception as e:
            logger.error(f"Failed to update metrics for jail '{jail_name}'", exc_info=e)
            report_error()
            continue
        
    current_attackers = set()
    known_attackers_set = set(known_attackers)
    for jail_name in set(known_jails) | set(jail_names):
        if jail_name not in jail_names:
            # Jail has been removed since last scrape
            del known_jails[jail_name]
            continue
        
        # Add the contents of the jail
        current_attackers.update(known_jails[jail_name])
        
    new_attackers = current_attackers - known_attackers_set
    forgiven_attackers = known_attackers_set - current_attackers
    outdated_attackers = []
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    for ip_address, timestamp in known_attackers.items():
        if current_time - timestamp > ATTACKER_DATA_REFRESH_INTERVAL:
            outdated_attackers.append(ip_address)
            
    for response in api.query(list(set(outdated_attackers) | new_attackers)):
        if response.status == QueryResult.Fail:
            logger.warning(f"Failed to get data for attacker '{response.host}': {response.error_message}")
            continue
        
        host: HostData = response.result
        try:
            metrics.add_attacker(host)
            known_attackers[host.host] = int(datetime.datetime.timestamp(host.fetched_at))
            logger.debug(f"Added/updated attacker '{response.host}")
        except Exception as e:
            logger.error(f"Failed to add/update attacker '{response.host}'", exc_info=e)
            report_error()
            
    for ip_address in forgiven_attackers:
        try:
            metrics.remove_attacker(ip_address)
            del known_attackers[ip_address]
            logger.debug(f"Removed attacker '{ip_address}")
        except Exception as e:
            logger.error(f"Failed to remove forgiven attacker: '{ip_address}'", exc_info=e)        
            report_error()
    
    logger.info(f"{len(new_attackers)} new attacker(s), {len(outdated_attackers)} updated, {len(forgiven_attackers)} forgiven")
    
def main():
    logger.info(f"Performing first update in {SCRAPE_INTERVAL_SECONDS} seconds")
    time.sleep(SCRAPE_INTERVAL_SECONDS)
    while True:
        try:
            perform_update()
        except Exception as e:
            logger.error("Failed to run update", exc_info=e)
            report_error()
        
        time.sleep(SCRAPE_INTERVAL_SECONDS)
    
if __name__ == "__main__":
    metrics.start_server(host=APP_HOST, port=APP_PORT)
    main()