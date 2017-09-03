import re
from tcp import *

class serverMySQL: #multiple contents
    def checkServerMySQLTCP(payloadToBeChecked):
        patternT1 = re.compile("substring\(", flags=2)
        # $HOME_NET 3306 destination msg:"SERVER-MYSQL Oracle MySQL Server XPath memory Corruption attempt"
        patternT2 = re.compile(",\.\.", flags=2)
        # $HOME_NET 3306 destination msg:"SERVER-MYSQL Oracle MySQL Server XPath memory Corruption attempt"


        if ((re.search(patternT2, payloadToBeChecked))and (TCP.getsourcePort()=="3306") and (re.search(patternT1, payloadToBeChecked))):
            #TCP.getsourcePort
            print("Alert!!!\t", "SERVER-MYSQL Oracle MySQL Server XPath memory Corruption attempt")