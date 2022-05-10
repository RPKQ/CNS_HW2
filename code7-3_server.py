# echo-server.py
# https://2019.www.torproject.org/docs/tor-onion-service.html.en?ref=hackernoon.com#four)

import socket

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 8080  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        print(conn.recv(1024).decode()) # Please enter the number shown above to proceed :
        captcha = str(input())
        conn.sendall(captcha.encode())

        print(conn.recv(1024).decode()) # Please enter your new password :
        conn.sendall(b"12345\n")
        print(b"12345") 
        print(conn.recv(1024).decode()) # response
