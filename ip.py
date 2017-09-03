import struct


class ip:
    def parseIP(self,data,socket):
        unpackedData = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version_IHL = unpackedData[0]
        version = version_IHL >> 4
        IHL = version_IHL & 0xf
        TOS = unpackedData[1]
        totalLength = unpackedData[2]
        ID = unpackedData[3]
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1fff
        TTL = unpackedData[5]
        protocol = unpackedData[6]
        checkSum = unpackedData[7]
        sourseAddress = socket.inet_ntoa(unpackedData[8])
        destinationAddress = socket.inet_ntoa(unpackedData[9])
        print("An IP packet with the size %i was Captured" % (totalLength))
        print("Raw data: ", ' ', data)
        print("\nParsed data")
        print("Version\t\t", ' ', str(version))
        print("Header Length\t\t", str(IHL * 4), "Bytes")
        print("Type of Service \t", ' ', self.getTOS(TOS))
        print("Length\t\t\t", ' ', str(totalLength))
        print("Identification\t\t\t", ' ', str(hex(ID)))  # '(' + ')' + str(ID)
        print("Flags\t\t\t", ' ', self.getFlags(flags))
        print("Fragment Offset \t", ' ', str(fragmentOffset))
        print("TTL \t\t\t", ' ', str(TTL))
        print("Protocol\t\t", ' ', self.getProtocol(protocol))
        print("Checksum\t\t", ' ', str(checkSum))
        print("Source\t\t\t", ' ', sourseAddress)
        print("Destination\t\t", ' ', destinationAddress)
        print("Payload \t", ' ', data[20:])
        # get the time of service and it is 8 bits long
    def getTOS(self,data):
        precedence = {0: "Routine", 1: "Priorty", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                      6: "Internetwork Control", 7: "Network Control"}
        delay = {0: "Normal delay", 1: "Low delay"}
        throughput = {0: "Normal throughput", 1: "high throughput"}
        reliability = {0: "Normal Reliability", 1: "High reliability"}
        cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

        D = data & 0x10
        D >>= 4
        T = data & 0x8
        T >>= 3
        R = data & 0x4
        R >>= 2
        M = data & 0x2
        M >>= 1

        tabs = "\n\t\t\t"
        TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
        return TOS

    def getFlags(self,data):
        flagR = {0: "0 - Reserved bit"}
        flagDf = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
        flagMf = {0: "0 - last fragment", 1: "1 - More fragments"}

        R = data & 0x8000
        R >>= 15
        Df = data & 0x4000
        Df >>= 14
        Mf = data & 0x2000
        Mf >>= 13

        tabs = "\n\t\t\t"
        flags = flagR[R] + tabs + flagDf[Df] + tabs + flagMf[Mf]
        return flags

    def getProtocol(self,data):
        protocol = {1: "Internet Control Message Protocol", 6: "Transmission Control Protocol",
                    17: "User Datagram Protocol"}
        return protocol[data]


