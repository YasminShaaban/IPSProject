import struct

class udp:
       def parseUDP(self,data):
        unpackedDataudp = struct.unpack("!HHHH", data[20:28])
        sourcePortudp = unpackedDataudp[0]
        destinationPortudp = unpackedDataudp[1]
        Length = unpackedDataudp[2]
        checkSumudp = unpackedDataudp[3]
        print('Source Port\t\t %s'%sourcePortudp)
        print("Destination Port\t %s"%destinationPortudp)
        print("Length of the UDP header %s"%Length)
        print("Checksum is \t\t %s"%checkSumudp)
        print("Payload UDP \t\t %s"%data[28:])

       def getsourcePort(self):
        data = self.recieveData(self.s);
        unpackedDataTcp = struct.unpack("!HHLLHHHH", data[20:40])
        sourcePort = unpackedDataTcp[0]
        return sourcePort;

       def getdestinationPort(self):
        data = self.recieveData(self.s);
        unpackedDataTcp = struct.unpack("!HHLLHHHH", data[20:40])
        destinationPort = unpackedDataTcp[1]
        return destinationPort;


