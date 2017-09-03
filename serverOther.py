import re
from tcp import TCP

class serverOther:
    def checkServerOtherTCP(payloadToBeChecked):
        patternT1 = re.compile('edit\.action\?', flags=2) #72
        #$HOME_NET $HTTP_PORTS destination (msg:"SERVER-OTHER Apache Struts2 skillName remote code execution attempt"
        patternT2=re.compile("skillName=\\x7B \\x28 \\x23",flags=2)#72
        patternT3=re.compile("SOAPAction\\x3A,flags=2")#101
        #$HOME_NET [$HTTP_PORTS,5555] destination (msg:"SERVER-OTHER MiniUPnPd ExecuteSoapAction buffer overflow attempt"
        patternT4=re.compile("\x75",flags=2)#109
        #$HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT5 = re.compile("nsrmm",flags=2)#109
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT6 = re.compile("mmpool", flags=2)  # 110
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT7 = re.compile("mmlocate", flags=2)  # 111
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT8 = re.compile("nsrjb", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT9 = re.compile("\\x18 \\x03 \\x03", flags=2)  # 645
        #$HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any
        # (msg:"SERVER-OTHER OpenSSL TLSv1.2 large heartbeat response - possible ssl heartbleed attempt"
        patternT10 = re.compile("\\x18 \\x03 \\x02", flags=2)  # 646
        # $HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any
        # (msg:"SERVER-OTHER OpenSSL TLSv1.1 large heartbeat response - possible ssl heartbleed attempt"
        patternT11 = re.compile("\\x18 \\x03 \\x00", flags=2)  # 647
        # $HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any
        # (msg:"SERVER-OTHER OpenSSL TLSv1 large heartbeat response - possible ssl heartbleed attempt"
        patternT12 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 648 --->652
        # $HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any
        # (msg:"SERVER-OTHER OpenSSL TLSv3 large heartbeat response - possible ssl heartbleed attempt"
        patternT13 = re.compile("\\x18 \\x03 \\x03", flags=2)  #
        #$EXTERNAL_NETany -> $HOME_NET[21, 25, 443, 465, 636, 992, 993, 995, 2484](msg:"SERVER-OTHER OpenSSL TLSv1.2 heartbeat read overrun attempt"
        patternT14 = re.compile("\\x18 \\x03 \\x02", flags=2)  #
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT15 = re.compile("\\x18 \\x03 \\x00", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT16 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT17 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT18 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT19 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"
        patternT20 = re.compile("\\x18 \\x03 \\x01", flags=2)  # 112
        # $HOME_NET 3000 (msg:"SERVER-OTHER EMC AlphaStor Device Manager command injection attempt"

        if ((re.search(patternT1, payloadToBeChecked))and (re.search(patternT2, payloadToBeChecked))):
            print("Alert!!!\t", "SERVER-OTHER Apache Struts2 skillName remote code execution attempt")
        if (re.search(patternT3, payloadToBeChecked)):
            print("Alert!!!\t", "SERVER-OTHER MiniUPnPd ExecuteSoapAction buffer overflow attempt")
        if (re.search(patternT4, payloadToBeChecked)and(TCP.getdestinationPort()=="3000") and re.search(patternT5, payloadToBeChecked)):
            print("Alert!!!\t", "SERVER-OTHER EMC AlphaStor Device Manager command injection attempt")
        if (re.search(patternT4, payloadToBeChecked) and (TCP.getdestinationPort() == "3000") and re.search(patternT6,payloadToBeChecked)):
                print("Alert!!!\t", "SERVER-OTHER EMC AlphaStor Device Manager command injection attempt")
        if (re.search(patternT4, payloadToBeChecked) and (TCP.getdestinationPort()== "3000") and re.search(patternT7, payloadToBeChecked)):
            print("Alert!!!\t", "SERVER-OTHER EMC AlphaStor Device Manager command injection attempt")
        if (re.search(patternT4, payloadToBeChecked) and (TCP.getdestinationPort() == "3000") and re.search(patternT8, payloadToBeChecked)):
            print("Alert!!!\t", "SERVER-OTHER EMC AlphaStor Device Manager command injection attempt")
        if (re.search(patternT9, payloadToBeChecked))and (TCP.getsourcePort()=="21" or TCP.getsourcePort()=="443" or TCP.getsourcePort()=="25" or TCP.getsourcePort()=="993" or TCP.getsourcePort()=="992" or TCP.getsourcePort()=="636" or TCP.getsourcePort()=="465"or TCP.getsourcePort()=="995" or TCP.getsourcePort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1.2 large heartbeat response - possible ssl heartbleed attempt")
        if (re.search(patternT10, payloadToBeChecked))and (TCP.getsourcePort()=="21" or TCP.getsourcePort()=="443" or TCP.getsourcePort()=="25" or TCP.getsourcePort()=="993" or TCP.getsourcePort()=="992" or TCP.getsourcePort()=="636" or TCP.getsourcePort()=="465"or TCP.getsourcePort()=="995" or TCP.getsourcePort()=="2484" ):
                print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1.1 large heartbeat response - possible ssl heartbleed attempt")
        if (re.search(patternT11, payloadToBeChecked))and (TCP.getsourcePort()=="21" or TCP.getsourcePort()=="443" or TCP.getsourcePort()=="25" or TCP.getsourcePort()=="993" or TCP.getsourcePort()=="992" or TCP.getsourcePort()=="636" or TCP.getsourcePort()=="465"or TCP.getsourcePort()=="995" or TCP.getsourcePort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1 large heartbeat response - possible ssl heartbleed attempt")
        if (re.search(patternT12, payloadToBeChecked))and (TCP.getsourcePort()=="21" or TCP.getsourcePort()=="443" or TCP.getsourcePort()=="25" or TCP.getsourcePort()=="993" or TCP.getsourcePort()=="992" or TCP.getsourcePort()=="636" or TCP.getsourcePort()=="465"or TCP.getsourcePort()=="995" or TCP.getsourcePort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv3 large heartbeat response - possible ssl heartbleed attempt")
        if (re.search(patternT9, payloadToBeChecked))and (TCP.getdestinationPort()=="21" or TCP.getdestinationPort()=="443" or TCP.getdestinationPort()=="25" or TCP.getdestinationPort()=="993" or TCP.getdestinationPort()=="992" or TCP.getdestinationPort()=="636" or TCP.getdestinationPort()=="465"or TCP.getdestinationPort()=="995" or TCP.getdestinationPort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1.2 heartbeat read overrun attempt")
        if (re.search(patternT10, payloadToBeChecked))and (TCP.getdestinationPort()=="21" or TCP.getdestinationPort()=="443" or TCP.getdestinationPort()=="25" or TCP.getdestinationPort()=="993" or TCP.getdestinationPort()=="992" or TCP.getdestinationPort()=="636" or TCP.getdestinationPort()=="465"or TCP.getdestinationPort()=="995" or TCP.getdestinationPort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1.1 heartbeat read overrun attempt")
        if (re.search(patternT11, payloadToBeChecked))and (TCP.getdestinationPort()=="21" or TCP.getdestinationPort()=="443" or TCP.getdestinationPort()=="25" or TCP.getdestinationPort()=="993" or TCP.getdestinationPort()=="992" or TCP.getdestinationPort()=="636" or TCP.getdestinationPort()=="465"or TCP.getdestinationPort()=="995" or TCP.getdestinationPort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv1 heartbeat read overrun attempt")
        if (re.search(patternT12, payloadToBeChecked))and (TCP.getdestinationPort()=="21" or TCP.getdestinationPort()=="443" or TCP.getdestinationPort()=="25" or TCP.getdestinationPort()=="993" or TCP.getdestinationPort()=="992" or TCP.getdestinationPort()=="636" or TCP.getdestinationPort()=="465"or TCP.getdestinationPort()=="995" or TCP.getdestinationPort()=="2484" ):
            print("Alert!!!\t", "SERVER-OTHER OpenSSL TLSv3 heartbeat read overrun attempt")
