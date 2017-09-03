
import struct

class icmp:
    def getTypeICMP(self,TypeICMP):
        typeicmp = {0: "Echo reply.", 3: "Destination unreachable.", 4: "Source quench.", 5: "Redirect.",
                    6: "Alternate host address.", 8: "Echo request.", 9: "Router advertisement.",
                    10: "Router solicitation.", 11: "Time exceeded.", 12: "Parameter problem.",
                    13: "Timestamp request.",
                    14: "Timestamp reply.", 15: "Information request. Obsolete.", 16: "Information reply. Obsolete.",
                    17: "Address mask request.", 18: "Address mask reply.", 30: "Traceroute.", 31: "Conversion error.",
                    32: "Mobile Host Redirect.", 33: "IPv6 Where-Are-You.", 34: "IPv6 I-Am-Here.",
                    35: "Mobile Registration Request.", 36: "Mobile Registration Reply.", 37: "Domain Name request.",
                    38: "Domain Name reply.", 39: "SKIP Algorithm Discovery Protocol.",
                    40: "Photuris, Security failures.",
                    41: "Experimental mobility protocols."}
        return typeicmp[TypeICMP] #return value beside the index TypeICMP
    def parseICMP(self,data):
            unpackedDataICMP = struct.unpack("!BBH", data[20:24])
            unpackedDataUdp = struct.unpack("!HHHH", data[20:28])
            TypeICMP = unpackedDataUdp[0]
            codeICMP = unpackedDataUdp[1]
            checkSumICMP = unpackedDataUdp[2]

            print("Type of ICMP: \t\t ", ' ', self.getTypeICMP(TypeICMP))
            print("Code of ICMP: \t ", ' ', codeICMP)
            print("ICMP header checksum:  ", ' ',checkSumICMP)
            print("Payload ICMP \t", ' ', data[24:])


