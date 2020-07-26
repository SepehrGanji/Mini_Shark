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
    return [get_mac(dest_mac), get_mac(src_mac), htons(prot), data[14:]]

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

def printDNS(dns_hh):
    print("-DNS :")
    print("\tID: " + str(dns_hh[0])
    + ", flags: " + dns_hh[1]
    + ", QuestionCount: " + str(dns_hh[2]))
    print("\tAnswerCount: " + str(dns_hh[3])
    + ", NSCount: " + str(dns_hh[4])
    + ", AdditionalInfoCount: " + str(dns_h[5]))
    print("\tContent: " + str(dns_hh[-1]))

#Start of Program
f = open("Packets.pcap", "w")
f.close()
connection = socket(AF_PACKET, SOCK_RAW, ntohs(3))

while(True):
    myfile = open("Packets.pcap", "ab")
    data, addr = connection.recvfrom(65535)
    myfile.write(data)
    myfile.close()
    print("********NewPacket********")
    #Ethernet
    ether_header = ether(data)
    print("-Ethernet Frame:")
    print("\tDestination MAC: " + ether_header[0] + ", Source MAC: " + ether_header[1]
    + ", Protocol: " + str(ether_header[2]))
    #End Ethernet
    if(ether_header[2] == 8): #IP
        ip_header = ip(ether_header[-1])
        print("-IP Packet:")
        print("\tVersion: " + str(ip_header[0])
        + ", HeaderLenght: " + str(ip_header[1])
        + ", TOS: " + str(ip_header[2])
        + ", Totlal length: " + str(ip_header[3]))
        print("\tIdentification: " + str(ip_header[4])
        + ", IPFlags: " + str(ip_header[5])
        + ", Offset: " + str(ip_header[6])
        + ", TTL: " + str(ip_header[7]))
        print("\tProtocol: " + str(ip_header[8])
        + ", HeaderChecksum: " + ip_header[9]
        + ", SourceIP: " + ip_header[10]
        + ", DestinationIP: " + ip_header[11])
        #End IP
        if(ip_header[8] == 1): #ICMP
            icmp_header = icmp(ip_header[-1])
            print("-ICMP segment:")
            print("\tType: " + str(icmp_header[0])
            +", Code: " + str(icmp_header[1])
            + ", Checksum: " + icmp_header[2])
            print("\tContent: " + icmp_header[3])
            #End ICMP
        elif(ip_header[8] == 6): #TCP
            tcp_header = tcp(ip_header[-1])
            print("-TCP Segment:")
            print("\tSourcePort: " + str(tcp_header[0])
            + ", DestinationPort: " + str(tcp_header[1])
            + ", SequenceNum: " + str(tcp_header[2])
            + ", ACKNum: " + str(tcp_header[3]))
            if(len(tcp_header) == 14):
                print("\tDataOffset: "+ str(tcp_header[4])
                + ", URGFlag: " + str(tcp_header[5])
                + ", ACKFlag: " + str(tcp_header[6]))
                print("\tRSTFlag: " + str(tcp_header[7])
                + ", SYNFlag: " + str(tcp_header[8])
                + ", FINFlag: " + str(tcp_header[9]))
                print("\tWindowSize: " + str(tcp_header[10])
                + ", CheckSum: " + tcp_header[11]
                + ", Urgent: " + str(tcp_header[12]))
            else:
                print("\tCan't parse rest of segment: "
                + str(tcp_header[-1]))
            #End TCP
            if(tcp_header[0] == 80 or tcp_header[1] == 80):
                http_h = http(tcp_header[-1])
                print("-HTTP " + http_h[0])
                print(http_h[1])
            elif(tcp_header[0] == 53 or tcp_header[1] == 53):
                dns_h = dns(tcp_header[-1])
                printDNS(dns_h)
            else:
                print("-Unknown Application Layer:")
                print(tcp_header[-1])
        elif(ip_header[8] == 17): #UDP
            udp_header = udp(ip_header[-1])
            print("-UDP Datagram:")
            print("\tSourcePort: " + str(udp_header[0])
            + ", DestinationPort: " + str(udp_header[1])
            + ", Length: " + str(udp_header[2])
            + ", CheckSum: " + udp_header[3])
            #End UDP
            if(udp_header[0] == 53 or udp_header[1] == 53):
                dns_h = dns(udp_header[-1])
                printDNS(dns_h)
            else:
                print("-Unknown Application Layer:")
                print(udp_header[-1])
        else:#UnknownTransport
            print("-Unknown Transport Layer:")
            print(ip_header[-1])
    elif(ether_header[2] == 1544): #ARP
        arp_h = arp(ether_header[-1])
        print("-ARP Packet:")
        print("\tHardware type: " + arp_h[0]
        + ", Protocol type: " + arp_h[1]
        + ", Hardware address length: " + arp_h[2])
        print("\tProtocol address length: " + arp_h[3]
        + ", Operation: " + arp_h[4])
        print("\tData: " + arp_h[-1])
    else: #UnknownIP
        print("-Unknown Network Layer:")
        print(ether_header[-1])
