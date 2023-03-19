import dpkt;
import ipaddress
import datetime
from dpkt.tcp import TCP
from dpkt.udp import UDP
from dpkt.ip import IP
from dpkt.utils import inet_to_str

class device:
    def __init__ (self):
        self.IP = ''
        self.send = []
        self.recieve = []

class protocal():
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

devicelst = []
timestamplst = []
sendlst = []
recievelst = []

def getdevice(pcapf):
    path = 'pcapfiles/' + pcapf
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        timestamplst.append(str(datetime.datetime.utcfromtimestamp(ts)))
        if isinstance(ip, IP): 
            ipstr = inet_to_str(ip.src)
            ipint = ipaddress.ip_address(ipstr)
            lower = ipaddress.ip_address('10.42.0.2')
            upper = ipaddress.ip_address('10.42.0.255')
            if lower <= ipint <= upper and ipstr not in devicelst:
                devicelst.append(ipstr)
        else: continue
    return devicelst

def getprotocol(pcapf):
    path = 'pcapfiles/' + pcapf
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    pclass = protocal()
    

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if isinstance(ip, IP): data = ip.data
        else: continue
        if isinstance(data, TCP):
            dport = data.dport
            match dport:
                case 80:
                    pclass.HTTP += 1
                case 443:
                    pclass.HTTPS += 1
                case 53:
                    pclass.DNS += 1
                case 21:
                    pclass.FTP += 1
                case 22:
                    pclass.SSH += 1
                case 3389:
                    pclass.TELNET += 1
                case 35:
                    pclass.SMTP += 1
                case 110:
                    pclass.POP3 += 1
        elif isinstance(data, UDP):
            dport = data.dport
            match dport:
                case 67:
                    pclass.DHCP += 1
                case 1023:
                    pclass.NTP += 1
        else: continue
    
    return pclass



def getSendandRecieve(pcapf):
    a=b=c=d=e=x=g=h=0
    path = 'pcapfiles/' + pcapf
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if isinstance(ip, IP):
            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)
            match src:
                case '10.42.0.32':
                    a += 1
                case '10.42.0.149':
                    b += 1
                case '10.42.0.193':
                    c += 1
                case '10.42.0.52':
                    d += 1
            match dst:
                case '10.42.0.32':
                    e += 1
                case '10.42.0.149':
                    x += 1
                case '10.42.0.193':
                    g += 1
                case '10.42.0.52':
                    h += 1
        else: continue
    
    sendlst.extend((a,b,c,d))
    recievelst.extend((e,x,g,h))
    return 0

device1lst = []
device2lst = []
device3lst = []
device4lst = []


    



def runtest():
    pcap = 'project1_part2.pcap'
    pclass = getprotocol(pcap)
    getdevice(pcap)
    getSendandRecieve(pcap)
    starttime = timestamplst[0]
    endtime = timestamplst[len(timestamplst) - 1]
    print('Protocol used: \n')
    print('#HTTP: ' + str(pclass.HTTP))
    print('#HTTPS: ' +str(pclass.HTTPS))
    print('#DNS: ' + str(pclass.DNS))
    print('#FTP: ' + str(pclass.FTP))
    print('#SSH: ' + str(pclass.SSH))
    print('#DHCP: ' + str(pclass.DHCP))
    print('#TELNET: ' + str(pclass.TELNET))
    print('#SMTP: ' + str(pclass.SMTP))
    print('#POP3: ' + str(pclass.POP3))
    print('#NTP: ' + str(pclass.NTP))
    print('\n-----------\n')
    print('IP address of devices: ')
    for device in devicelst:
        print(device)
    print('\n-----------\n')
    print('#Packets sent:')
    for i in range(0,4):
        print(devicelst[i] + ': ' + str(sendlst[i]))
    print('\n-----------\n')
    print('#Packets recieved: ')
    for i in range(0,4):
        print(devicelst[i] + ': ' + str(recievelst[i]))
    print('\n-----------\n')
    print('Time to capture: \n')
    print(starttime + ' -> ' + endtime)

runtest()

