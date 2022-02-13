#!/usr/bin/env python3
# Modified by WildZarek

import http.server
import signal
import ssl
import sys

def exit_handler(sig, frame):
    print("\n[!] Exiting...")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

if len(sys.argv) == 3:
   local_ip = sys.argv[1]
   local_port = sys.argv[2]
   if local_port.isnumeric():
      local_port = int(local_port)
   httpd = http.server.HTTPServer((local_ip, local_port), http.server.SimpleHTTPRequestHandler)
   httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)

   print(f"Serving HTTPS on {local_ip} port {local_port} (https://{local_ip}:{local_port}/) ...")
   httpd.serve_forever()
else:
   print(f"[!] Usage: sudo python3 {sys.argv[0]} <local_ip> <local_port>")
   sys.exit(1)
