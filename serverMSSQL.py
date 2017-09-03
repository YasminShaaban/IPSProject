import re

class serverMSSQL: #multiple contents
    def checkServerMSSSQLTCP(payloadToBeChecked):
        patternT1 = re.compile("sp_replicationdboption", flags=2)
        # $SQL_SERVERS 1024:5000 destination ip then destination port
        patternT2 = re.compile("SET SHOWPLAN_XML ON", flags=2)
        # $SQL_SERVERS 1024:5000 destination ip then destination port
        patternT3 = re.compile("@optname", flags=2)
          # $SQL_SERVERS 1024:5000 destination ip then destination port
        patternT4 = re.compile("@value", flags=2)
          # $SQL_SERVERS 1024:5000 destination ip then destination port
        patternT5 = re.compile("true", flags=2)
           # $SQL_SERVERS 1024:5000 destination ip then destination port

        if ((re.search(patternT1, payloadToBeChecked)) and (re.search(patternT2, payloadToBeChecked)) and (re.search(patternT3, payloadToBeChecked)) and (re.search(patternT4, payloadToBeChecked)) and (re.search(patternT5, payloadToBeChecked))):
            print("Alert!!!\t", "SERVER-MSSQL Microsoft SQL Server transcational replication and showxmlplan enabled "
                                "remote code execution attempt")
