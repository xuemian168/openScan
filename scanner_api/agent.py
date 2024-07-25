import requests
import platform
import psutil
import time

while True:
    client_os = platform.system()
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    processes = [p.name() for p in psutil.process_iter(attrs=['name'])]

    data = {
        'client_os': client_os,
        'cpu_usage': cpu_usage,
        'ram_usage': ram_usage,
        'processes': processes,
    }

    response = requests.post('http://10.10.10.111/api/receive_data.do', data=data)
    print(response.json())

    time.sleep(30)
