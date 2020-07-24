from socket import *

connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))
#Here we must have while loop
data, addr = connection.recvfrom(65535)
print(data)
print(addr)