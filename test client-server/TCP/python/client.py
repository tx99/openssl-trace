# client
import socket
import ssl
import time
import random
import os

host_addr = '127.0.0.1'
host_port = 8082

server_sni_hostname = 'test.com'

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))
print("SSL established.")

client_pid = os.getpid()
print(f"Client PID: {client_pid}")

count = 0
while True:
    time.sleep(1)
    secret = random.randint(0, 1024 * 1024 * 1024)
    conn.send("Client random number {} is {}".format(count, secret).encode())
    data = conn.recv(1024)
    print(data.decode())
    count += 1

print("Closing connection")
conn.close()