import re


class serverOracle:
    def checkServerOracleTCP(self,payloadToBeChecked):
        patternT1 = re.compile("\(DESCRIPTION=\(CONNECT_DATA=\(SERVICE_NAME=", flags=2)
        # $HOME_NET $ORACLE_PORTS source  msg:"SERVER-ORACLE Oracle connection established"

        if ((re.search(patternT1, payloadToBeChecked))):
            print("Alert!!!\t", "SERVER-ORACLE Oracle connection established")

