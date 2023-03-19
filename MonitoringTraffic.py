import dpkt;
from dpkt.tcp import TCP
from dpkt.udp import UDP
from dpkt.ip import IP
from dpkt.utils import inet_to_str

class pcapinfo():
    def __init__(self):
        self.HTTP = 0
        self.HTTPS = 0
        self.DNS = 0
        self.FTP = 0
        self.SSH = 0
        self.DHCP = 0
        self.TELNET = 0
        self.SMTP = 0
        self.POP3 = 0
        self.NTP = 0
        self.Packets = 0

def extractinfo(pcapf):
    path = 'pcapfiles/' + pcapf
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    info = pcapinfo()

    for ts, buf in pcap:
        info.Packets += 1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        data = ip.data
        if isinstance(data, TCP):
            dport = data.dport
            match dport:
                case 80:
                    info.HTTP += 1
                case 443:
                    info.HTTPS += 1
                case 53:
                    info.DNS += 1
                case 21:
                    info.FTP += 1
                case 22:
                    info.SSH += 1
                case 3389:
                    info.TELNET += 1
                case 35:
                    info.SMTP += 1
                case 110:
                    info.POP3 += 1
        elif isinstance(data, UDP):
            dport = data.dport
            match dport:
                case 67:
                    info.DHCP += 1
                case 1023:
                    info.NTP += 1
        else: continue
    
    return info


def getuniqueIPaddress(pcapf):
    path = 'pcapfiles/' + pcapf
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    lst = []
    
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if isinstance(ip, IP):
            dstip = inet_to_str(ip.dst)
            if(dstip not in lst): 
                lst.append(dstip)
        else: continue
    return lst

def runtest():
    f = input('Enter a pcapfile: ')
    info = extractinfo(f)
    lst = getuniqueIPaddress(f)
    print('Pcapinfo: \n')
    print('#HTTP: ' + str(info.HTTP))
    print('#HTTPS: ' +str(info.HTTPS))
    print('#DNS: ' + str(info.DNS))
    print('#FTP: ' + str(info.FTP))
    print('#SSH: ' + str(info.SSH))
    print('#DHCP: ' + str(info.DHCP))
    print('#TELNET: ' + str(info.TELNET))
    print('#SMTP: ' + str(info.SMTP))
    print('#POP3: ' + str(info.POP3))
    print('#NTP: ' + str(info.NTP))
    print('#Packets: ' + str(info.Packets))
    print('\n-----------\n')
    print('Unique IP address: \n')
    for element in lst:
        print(element)
    print('#Unique IP address: ' + str(len(lst)))

runtest()
















