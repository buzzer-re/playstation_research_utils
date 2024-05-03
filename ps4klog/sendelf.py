import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
bin_path = sys.argv[3]

s = socket.socket()
b = open(bin_path, "rb").read()

print("Connecting to the PS...")
try:
    s.connect((ip, port))
    print("Connected! Sending payload!")
except:
    print("Unable to connect")
    sys.exit(0)
    
s.send(b)
print("Closed")
s.close()