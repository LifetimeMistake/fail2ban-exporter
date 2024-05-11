__version__ = "0.1.0"
IPAPI_URL = "http://ip-api.com"
IPAPI_BATCH_SIZE = 100
IPAPI_SYSTEM_FIELDS = ["status", "message", "query"]
IPAPI_DEFAULT_FIELDS = [
    "country", "countryCode", "region", 
    "regionName", "city", "zip", "lat", "lon", "timezone",
    "isp" ,"org", "as", "mobile", "proxy", "hosting"
]
IPAPI_USER_AGENT = f"iptracker/{__version__}"
DEFAULT_METRICS_PORT = 9090