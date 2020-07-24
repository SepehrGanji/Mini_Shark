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

def arp(data):
    pass

def ip(data):
    mydata = unpack('!BBHHHBBH4s4s', data[:20])
    return [(mydata[0] >> 4), (mydata[0] & 0xF) * 4, mydata[1], mydata[2],
    mydata[3], (mydata[4] >> 13), (mydata[4] & 0x1FFF), mydata[5],
    mydata[6], hex(mydata[7]), inet_ntoa(mydata[8]), inet_ntoa(mydata[9]),
    data[((data[0] & 0xF) * 4):]
    ]

def icmp(data):
    typ, code, checksum = unpack('!BBH', data[:4])
    return [typ, code, hex(checksum), repr(data[4:])]

def tcp(data):
    pass

def udp(data):
    pass

def http(data):
    pass

def dns(data):
    pass

connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while(True):
    data, addr = connection.recvfrom(65535)
    #TODO : save to file

    ether_header = ether(data)
    #TODO : print eth header

    if(ether_header[2] == 8): #IP
        ip_header = ip(ether_header[3])#IPv4/header length/type of serviece/total length
        #ID, Flag, Offset/TTL/Protocol/Header Checksum/src, dest
        if(ip_header[8] == 1):
            icmp_header = icmp(ip_header[-1])
            #TODO : print the rest
        elif(ip_header[8] == 6):
            pass
        elif(ip_header[8] == 17):
            pass
        else:
            pass
    elif(ether_header[2] == 1544): #ARP
        #TODO : arp
        pass
    else: #Unknown
        pass
