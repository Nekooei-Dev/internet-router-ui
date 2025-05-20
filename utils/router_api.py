from routeros_api import RouterOsApiPool
from config import Config

def connect_api():
    api_pool = RouterOsApiPool(
        Config.API_HOST,
        username=Config.API_USER,
        password=Config.API_PASS,
        port=Config.API_PORT,
        plaintext_login=True
    )
    api = api_pool.get_api()
    return api, api_pool
