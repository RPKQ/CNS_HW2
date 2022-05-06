import socket
from OpenSSL import SSL

### create domain key, domain certificate ###
# https://www.baeldung.com/openssl-self-signed-cert

### ssl/rootCA.crt ###
#  openssl s_client -showcerts -connect cns.csie.org:12345
#       - copy the rootCA certificate to ssl/rootCA.crt

### ssl/domain.key ###
# openssl genrsa -out domain.key 2048

### ssl/domain.ext ###
# should be the following content
# authorityKeyIdentifier=keyid,issuer
# basicConstraints=CA:FALSE
# subjectAltName = @alt_names
# [alt_names]
# DNS.1 = domain

### ssl/domain.crt ###
# openssl req -key domain.key -new -out domain.csr
#   - Enter: TW, Taiwan, Taipei, NTU CNS, student, cns.csie.org, alice@csie.ntu.edu.tw
# openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 365 -CAcreateserial -extfile domain.ext


### connect to server ###
# https://gist.github.com/shanemhansen/3853468
hostname = 'cns.csie.org'
port = 12345

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_certificate_chain_file("ssl/domain.crt")
context.use_privatekey_file("ssl/domain.key")

sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((hostname, port))

print(sock.recv(1024))
print(sock.recv(1024))
print(sock.recv(1024))
print(sock.recv(1024)) # login
sock.sendall(b"Alice410\n")
print(sock.recv(1024)) # password
sock.sendall(b"catsarecute\n")
print(sock.recv(1024)) # Enter your command
sock.sendall(b"Alohomora!\n")
print(sock.recv(1024))
print(sock.recv(1024))