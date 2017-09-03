import socket
import sys
import struct
from appDetect import *
#from blackList import *
from browserFirefox import *
from tcp import *
from udp import *
from icmp import *
from ip import *
from pyspark import SparkContext




def recieveData(s):
    try:
        data = s.recvfrom(65565)
        return data[0]
    except socket.timeout:
        data = ' '
    except:
        print("An error happened")
        sys.exc_info()



    # the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)



data = recieveData(s)

unpackedData = struct.unpack("!BBHHHBBH4s4s", data[:20])
protocol = unpackedData[6]
ipobj=ip()
udpobj=udp()
icmpobj=icmp()
tcpobj=tcp()
# part for tcp protocol
if (ipobj.getProtocol(protocol) == "Transmission Control Protocol"):

        tcpobj.parseTCP(data)
        payloadTCP = data[40:]
    #   check payload if there is malicious signature
        appDetect.checkAppDetectTCP(str(payloadTCP))
        #blackList.checkBlackListTCP(str(payloadTCP))
        browserFirefox.checkbrowserFirefoxTCP(str(payloadTCP))

       # part for udp protocol
if (ipobj.getProtocol(protocol) == "User Datagram Protocol"):
       udpobj.parseUDP(data)

      # part for ICMP protocol
if (ipobj.getProtocol(protocol) == "Internet Control Message Protocol"):
      icmpobj.parseICMP(data)

     # disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)