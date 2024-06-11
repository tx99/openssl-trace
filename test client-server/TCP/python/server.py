#server
import socket
import ssl
import time
import random
import os

def generate_certificates():
    # Generate server certificate and key using opnssl
    os.system("openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj '/CN=test.com'")

generate_certificates()

listen_addr = '127.0.0.1'
listen_port = 8082
server_cert = 'server.crt'
server_key = 'server.key'

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)

bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

while True:
    print("Waiting for client")
    newsocket, fromaddr = bindsocket.accept()
    print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
    conn = context.wrap_socket(newsocket, server_side=True)
    print("SSL established.")

    count = 0
    while True:
        time.sleep(1)
        data = conn.recv(1024)
        print(data.decode())
        secret = random.randint(0, 1024 * 1024 * 1024)
        conn.send("Server random number {} is {}".format(count, secret).encode())
        count += 1

print("Closing connection")
conn.shutdown(socket.SHUT_RDWR)
conn.close()