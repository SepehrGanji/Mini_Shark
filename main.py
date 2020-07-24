from socket import *
from struct import *

def get_mac(mac):
    macint = int.from_bytes(mac, 'big')
    if type(macint) != int:
        raise ValueError('invalid integer')
    return ':'.join(['{}{}'.format(a, b)
                     for a, b
                     in zip(*[iter('{:012x}'.format(macint))]*2)])

def ether(data):
    dest_mac, src_mac, prot = unpack('! 6s 6s H', data[:14])
    return [get_mac(src_mac), get_mac(dest_mac), htons(prot), data[14:]]

connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while(True):
    data, addr = connection.recvfrom(65535)
    #TODO : save to file
    ether_header = ether(data)
    #TODO : ARP (1544)
    
    break
