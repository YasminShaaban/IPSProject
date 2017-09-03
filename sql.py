import re
from tcp import *

class SQl:
    def checkSQlTCP(payloadToBeChecked):
        patternT1 = re.compile("Login failed for user 'sa'", flags=2) # --->34
        #msg:"SQL sa login failed" from $SQL_SERVERS 1433 source
        patternT2 = re.compile("\/\*", flags=2) #same 1 -->62
        #msg:"SQL generic sql with comments injection attempt - GET parameter"
        patternT3 = re.compile("\*\/", flags=2)#same 1 --->62
        # msg:"SQL generic sql with comments injection attempt - GET parameter"
        patternT4 = re.compile("WinCCConnect", flags=2) #same 2   --->72
        #msg:"SQL WinCC DB default password security bypass attempt"
        patternT5 = re.compile("2WSXcder",flags=2)#same 2 --->72
        # msg:"SQL WinCC DB default password security bypass attempt" destination :$SQL_SERVERS 1433
        patternT6 = re.compile("1=0", flags=2) #--->73
        #msg:"SQL 1 = 0 - possible sql injection attempt"
        patternT7 = re.compile("1=1", flags=2)#-->74
        #msg: "SQL 1 = 1 - possible sql injection attempt"
        patternT8 = re.compile("\\x271\\x27=\\x271", flags=2)  # -->87 "|27|1|27|=|27|1"
        # msg: "SQL 1 = 1 - possible sql injection attempt"
        patternT9 = re.compile("%271%27%3D%271", flags=2)  # -->91
        # msg: "SQL 1 = 1 - possible sql injection attempt"
        patternT10 = re.compile("1%3D1", flags=2)  # -->92
        # msg: "SQL 1 = 1 - possible sql injection attempt"
        patternT11 = re.compile("IBM solidDB", flags=2)  # -->96
        #$SQL_SERVERS[1315, 2315] source ,msg:"SQL IBM SolidDB initial banner"
        patternT12 = re.compile("--", flags=2)  # -->98
        #msg:"SQL url ending in comment characters - possible sql injection attempt"
        patternT13 = re.compile("REPEAT\\x28", flags=2)  # -->101 same 3
        #50000 destination port, msg:"SQL IBM DB2 DATABASE SERVER SQL REPEAT Buffer Overflow"
        patternT14 = re.compile(",", flags=2)  # -->101 same 3
        # 50000 destination port, msg:"SQL IBM DB2 DATABASE SERVER SQL REPEAT Buffer Overflow"
        patternT15 = re.compile("xmlquery", flags=2)  # -->104 same 4
        # 50000 destination port ,msg:"SQL IBM DB2 Universal Database xmlquery buffer overflow attempt"
        patternT16 = re.compile("select", flags=2)  # -->104 same 4
        # 50000 destination port ,msg:"SQL IBM DB2 Universal Database xmlquery buffer overflow attempt"
        patternT17 = re.compile("exec_sdbinfo", flags=2)  # -->107
        # $SQL_SERVERS  desyination address ,7210 destination port,msg:"SQL SAP MaxDB shell command injection attempt"
        patternT18 = re.compile("User-Agent\\x3A", flags=2)  # -->113 same 5
        # 50000 destination port, msg:"SQL use of sleep function in HTTP header - likely SQL injection attempt"
        patternT19 = re.compile("sleep\(", flags=2)  # -->113 same 5
         # 50000 destination port, msg:"SQL use of sleep function in HTTP header - likely SQL injection attempt"
        if re.search(patternT1, payloadToBeChecked):
            print("Alert!!!\t", "SQL sa login failed")
        if re.search(patternT2, payloadToBeChecked) and re.search(patternT3, payloadToBeChecked) :
            print("Alert!!!\t", "SQL generic sql with comments injection attempt - GET parameter")
        if re.search(patternT4, payloadToBeChecked)and re.search(patternT5, payloadToBeChecked) and TCP.getdestinationPort()=="1433":
            print("Alert!!!\t", "SQL WinCC DB default password security bypass attempt")
        if re.search(patternT6, payloadToBeChecked):
            print("Alert!!!\t", "SQL 1 = 0 - possible sql injection attempt")
        if re.search(patternT7, payloadToBeChecked):
            print("Alert!!!\t", "SQL 1 = 1 - possible sql injection attempt")
        if re.search(patternT8, payloadToBeChecked):
            print("Alert!!!\t", "SQL 1 = 1 - possible sql injection attempt")
        if re.search(patternT9, payloadToBeChecked):
            print("Alert!!!\t", "SQL 1 = 1 - possible sql injection attempt")
        if re.search(patternT10, payloadToBeChecked):
            print("Alert!!!\t", "SQL 1 = 1 - possible sql injection attempt")
        if (re.search(patternT11, payloadToBeChecked)) and (TCP.getsourcePort()=="1315"or TCP.getsourcePort()=="2315"):
            print("Alert!!!\t", "SQL IBM SolidDB initial banner")
        if re.search(patternT12, payloadToBeChecked):
            print("Alert!!!\t", "SQL url ending in comment characters - possible sql injection attempt")
        if re.search(patternT13, payloadToBeChecked) and re.search(patternT14, payloadToBeChecked):
            print("Alert!!!\t","SQL IBM DB2 DATABASE SERVER SQL REPEAT Buffer Overflow")
        if re.search(patternT15, payloadToBeChecked) and re.search(patternT16, payloadToBeChecked):
            print("Alert!!!\t", "SQL IBM DB2 Universal Database xmlquery buffer overflow attempt")
        if re.search(patternT17, payloadToBeChecked) and TCP.getdestinationPort()=="7210":
            print("Alert!!!\t", "SQL SAP MaxDB shell command injection attempt")
        if re.search(patternT18, payloadToBeChecked) and re.search(patternT19, payloadToBeChecked) and TCP.getdestinationPort()=="50000":
            print("Alert!!!\t", "SQL use of sleep function in HTTP header - likely SQL injection attempt")

