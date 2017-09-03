import re


class appDetect:
    def checkAppDetectTCP(payloadToBeChecked):
        patternT1 = re.compile("Acunetix-", flags=2)
        patternT2 = re.compile("\/server-info", flags=2)

        if re.search(patternT1, payloadToBeChecked):
            print("Alert!!!\t", "APP-DETECT Acunetix web vulnerability scan attempt")
        if re.search(patternT2, payloadToBeChecked):
            print("Alert!!!\t", "APP-DETECT Apple iTunes client request for server info")

