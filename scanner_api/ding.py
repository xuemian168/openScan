import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from portscan.models import Settings
import requests

webhook = Settings.objects.get(title="ding_webhook").value
print(webhook)
headers = {"Content-Type": "application/json", "Charset": "UTF-8"}


def get_timestamp_and_sign():
    timestamp = str(round(time.time() * 1000))
    secret = Settings.objects.get(title="ding_secret").value
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return timestamp, sign


def dingding_post(text):
    timestamp, sign = get_timestamp_and_sign()

    data = {
        "msgtype": "text",
        "text": {"content": text},
        "at": {"isAtAll": False}
    }

    print(json.dumps(data))

    webhook_url = f'{webhook}&timestamp={timestamp}&sign={sign}'
    print(webhook_url)
    res = requests.post(url=webhook_url, data=json.dumps(data), headers=headers, verify=False)
    print(res.text)


def ding_diy(data):
    timestamp, sign = get_timestamp_and_sign()
    webhook_url = f'{webhook}&timestamp={timestamp}&sign={sign}'
    res = requests.post(url=webhook_url, data=json.dumps(data), headers=headers, verify=False)
    print(res.text)
