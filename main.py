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

def ip(data):
    mydata = unpack('!BBHHHBBH4s4s', data[:20])
    return [(mydata[0] >> 4), (mydata[0] & 0xF) * 4, mydata[1], mydata[2],
    mydata[3], (mydata[4] >> 13), (mydata[4] & 0x1FFF), mydata[5],
    mydata[6], hex(mydata[7]), inet_ntoa(mydata[8]), inet_ntoa(mydata[9]),
    data[((data[0] & 0xF) * 4):]
    ]

connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while(True):
    data, addr = connection.recvfrom(65535)
    #TODO : save to file

    ether_header = ether(data)
    #TODO : ARP (1544)

    ip_header = ip(ether_header[3])
    #0 : 4 //IPv4
    #1 : 20-24 //header length
    #2 : 0 //type of serviece
    #3 : //total length
    #4, 5, 6 : ID, Flag, Offset
    #7 : TTL
    #8 : Protocol
    #9 : Header Checksum
    #10, 11 : src, dest
    
    
