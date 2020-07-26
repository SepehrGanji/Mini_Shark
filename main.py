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
    dest_mac, src_mac, prot = unpack('!6s6sH', data[:14])
    return [get_mac(src_mac), get_mac(dest_mac), htons(prot), data[14:]]

def arp(data):
    HRD, PRO, HLN, PLN, OP = unpack('!HHBBH', data[:8])
    return [
        HRD, PRO, HLN, PLN, OP, data[8:]
    ]

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
    mydata = unpack('!HHII2sHHH', data[:20])
    bites = bin(int.from_bytes(mydata[4], 'big'))
    mybites = bites[2:]
    try:
        return [
            mydata[0], mydata[1], mydata[2], mydata[3],
            mybites[:4], #Data offset
            mybites[10], #URG
            mybites[11], #ACK
            mybites[13], #RST
            mybites[14], #SYN
            mybites[15], #FIN
            mydata[5], hex(mydata[6]), mydata[7],
            data[20:]
        ]
    except:
        return [mydata[0], mydata[1], mydata[2], mydata[3], data[20:]]

def udp(data):
    mydata = unpack('!HHHH', data[:8])
    return [mydata[0], mydata[1], mydata[2]
    , hex(mydata[3]), data[8:]
    ]

def http(data):
    decoded_data = data.decode("utf-8", errors="ignore")
    #supporting GET & POST & Response
    method = ""
    if(decoded_data[0:3] == "GET"):
        method = "GET"
    elif(decoded_data[0:4] == "POST"):
        method = "POST"
    elif(decoded_data[0:4] == "HTTP"):
        method = "Response"
    else:
        method = "Unknown"
    return [
        method, decoded_data
    ]

def dns(data):
    header = data[:12]
    content = data[12:]
    header_data = unpack('!H2sHHHH', header)
    flags = bin(int.from_bytes(header_data[1], 'big'))
    return [
        header_data[0], flags[2:], header_data[2],
        header_data[3], header_data[4],
        header_data[5], content
    ]

connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while(True):
    data, addr = connection.recvfrom(65535)
    #TODO : save to file

    ether_header = ether(data)
    #TODO : print eth header

    if(ether_header[2] == 8): #IP
        ip_header = ip(ether_header[3])#IPv4/header length/type of serviece/total length
        #ID, Flag, Offset/TTL/Protocol/Header Checksum/src, dest
        if(ip_header[8] == 1): #ICMP
            icmp_header = icmp(ip_header[-1])
            #TODO : print the rest
        elif(ip_header[8] == 6): #TCP
            tcp_header = tcp(ip_header[-1])
            if(tcp_header[0] == 80 or tcp_header[1] == 80):
                http_h = http(tcp_header[-1])
                #TODO : print http
            elif(tcp_header[0] == 53 or tcp_header[1] == 53):
                dns_h = dns(udp_header[-1])
                #TODO : print the rest
            else:
                pass
                #TODO : print the rest
        elif(ip_header[8] == 17): #UDP
            udp_header = udp(ip_header[-1])
            if(udp_header[0] == 53 or udp_header[1] == 53):
                dns_h = dns(udp_header[-1])
                #TODO : print the rest
            else:
                pass
                #TODO print the rest
        else:
            pass
    elif(ether_header[2] == 1544): #ARP
        arp(ether_header[3])
        #TODO : print rest
    else: #Unknown
        pass
