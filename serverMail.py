import re
from tcp import TCP


class serverMail:
    def checkServerMailTCP(payloadToBeChecked):
        patternT1 = re.compile("HELO", flags=2) # --->124 same 1
        #$SMTP_SERVERS 25 destination ip and port msg:"SERVER-MAIL Exim gethostbyname heap buffer overflow attempt"
        patternT2 = re.compile("\\x0A", flags=2) #-->124 NOT |0A| same 1
        # $SMTP_SERVERS 25 destination ip and port msg:"SERVER-MAIL Exim gethostbyname heap buffer overflow attempt"
        patternT3 = re.compile("EHLO", flags=2)#--->125 not patternT2 same 1
        # $SMTP_SERVERS 25 destination ip and port msg:"SERVER-MAIL Exim gethostbyname heap buffer overflow attempt"
        patternT4 = re.compile("Content-Disposition\\x3A", flags=2) #same 2   --->145
        # $SMTP_SERVERS 25 msg "SERVER-MAIL Content-Disposition attachment"
        patternT5 = re.compile("attachment",flags=2)#same 2 --->145
        # $SMTP_SERVERS 25 msg "SERVER-MAIL Content-Disposition attachment"
        patternT6 = re.compile("WorldMail IMAP4 Server", flags=2) #--->148
        #$HOME_NET 143 source ip then source port msg:"SERVER-MAIL Qualcomm WorldMail Server Response"
        patternT7 = re.compile("BM", flags=2)#-->181
        # $SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Domino BMP color palette stack buffer overflow attempt"
        patternT8 = re.compile("\\x00 \\x00 \\x00 \\x00", flags=2)  # -->181
        # $SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Domino BMP color palette stack buffer overflow attempt"
        patternT9 = re.compile("\\x28 \\x00 \\x00 \\x00|", flags=2)  # -->181
        # $SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Domino BMP color palette stack buffer overflow attempt"
        patternT10 = re.compile("GIF89a", flags=2)  # -->184,185 -->$FILE_DATA_PORTS source port
        #$SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Lotus Domino Server nrouter.exe malformed GIF parsing remote exploit attempt"
        patternT11 = re.compile("\\x21 \\xF9 \\x04", flags=2)  # -->184,185-->$FILE_DATA_PORTS source port
        # $SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Lotus Domino Server nrouter.exe malformed GIF parsing remote exploit attempt"
        patternT12 = re.compile("\\x00 \\x2C", flags=2)  # -->184 ,185--> $FILE_DATA_PORTS source port
        # $SMTP_SERVERS 25 destination msg:"SERVER-MAIL IBM Lotus Domino Server nrouter.exe malformed GIF parsing remote exploit attempt"
        if re.search(patternT1, payloadToBeChecked) and (not re.search(patternT2, payloadToBeChecked)) and TCP.getdestinationPort()=="25":
            print("Alert!!!\t", "SQL sa login failed")
        if re.search(patternT3, payloadToBeChecked) and TCP.getdestinationPort()=="25":
            print("Alert!!!\t", "SERVER-MAIL Exim gethostbyname heap buffer overflow attempt")
        if re.search(patternT4, payloadToBeChecked) and re.search(patternT5, payloadToBeChecked) and TCP.getdestinationPort()=="25" :
            print("Alert!!!\t", "SERVER-MAIL Content-Disposition attachment")
        if re.search(patternT6, payloadToBeChecked) and TCP.getsourcePort()=="143":
            print("Alert!!!\t", "SERVER-MAIL Qualcomm WorldMail Server Response")
        if re.search(patternT7, payloadToBeChecked) and re.search(patternT8, payloadToBeChecked) and re.search(patternT9, payloadToBeChecked) and TCP.getdestinationPort()=="25":
            print("Alert!!!\t", "SERVER-MAIL IBM Domino BMP color palette stack buffer overflow attempt")
        if re.search(patternT10, payloadToBeChecked) and re.search(patternT11, payloadToBeChecked) and re.search(patternT12, payloadToBeChecked) and TCP.getdestinationPort()=="25" :
            print("Alert!!!\t", "SERVER-MAIL IBM Lotus Domino Server nrouter.exe malformed GIF parsing remote exploit attempt")

