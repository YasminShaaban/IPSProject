import struct
#from IPSMain import *
class tcp:

   def parseTCP (self,data):
       unpackedDataTcp = struct.unpack("!HHLLHHHH", self.data[20:40])
       sourcePort = unpackedDataTcp[0]
       destinationPort = unpackedDataTcp[1]
       sequenceNumber = unpackedDataTcp[2]
       acknowledgmentNumber = unpackedDataTcp[3]
       dataOffset = (unpackedDataTcp[4] & 0xf000) >> 12
       reservedTcp = (unpackedDataTcp[4] & 0x0e00) >> 9
       Notification = (unpackedDataTcp[4] & 0x0100) >> 8
       Congestion = (unpackedDataTcp[4] & 0x0080) >> 7
       Explicit = (unpackedDataTcp[4] & 0x0040) >> 6
       ControlU = (unpackedDataTcp[4] & 0x0020) >> 5
       ControlA = (unpackedDataTcp[4] & 0x0010) >> 4
       ControlP = (unpackedDataTcp[4] & 0x0008) >> 3
       ControlR = (unpackedDataTcp[4] & 0x0004) >> 2
       ControlS = (unpackedDataTcp[4] & 0x0002) >> 1
       ControlF = (unpackedDataTcp[4] & 0x0001)
       window = unpackedDataTcp[5]
       checkSumTCP = unpackedDataTcp[6]
       UrgentPointer = unpackedDataTcp[7]
       print("Source Port\t\t %s"%sourcePort)
       print("Destination Port\t ", ' ', destinationPort)
       print("Sequence Number \t", ' ', sequenceNumber)
       print("Acknowledgment \t\t", ' ', acknowledgmentNumber)
       print("Data Offset \t\t", ' ', dataOffset)
       print("Reserved in TCP \t", ' ', reservedTcp)
       print("Notification bit ", "(N, NS, Nonce Sum)\t", Notification)
       print("Congestion bit ", "(C, CWR)\t\t", Congestion)
       print("Explicit bit ", "(E, ECE, ECN-Echo)\t", Explicit)
       print("Urgent pointer valid flag\t\t", ' ', ControlU)
       print("Acknowledgment number valid flag\t", ' ', ControlA)
       print("Push flag\t\t\t\t", ' ', ControlP)
       print("Reset connection flag\t\t\t", ' ', ControlR)
       print("Synchronize sequence numbers flag\t", ' ', ControlS)
       print("End of data flag\t\t\t", ' ', ControlF)
       print(
           "The number of data bytes beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept\t",
           ' ', window)
       print("Checksum is \t\t ", ' ', checkSumTCP)
       print(
           "If the URG bit is set, this field points to the sequence number of the last byte in a sequence of urgent data.\t",
           ' ', UrgentPointer)
       print("Payload TCP \t", ' ', data[40:])


   def getsourcePort(self):
       data=self.recieveData(self.s);
       unpackedDataTcp = struct.unpack("!HHLLHHHH", data[20:40])
       sourcePort = unpackedDataTcp[0]
       return sourcePort;

   def getdestinationPort(self):
       data = self.recieveData(self.s);
       unpackedDataTcp = struct.unpack("!HHLLHHHH", data[20:40])
       destinationPort = unpackedDataTcp[1]
       return destinationPort;

