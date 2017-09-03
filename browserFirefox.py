import re


class browserFirefox:
    def checkbrowserFirefoxTCP(self,payloadToBeChecked):
        patternT1 = re.compile("readystatechange\|addEventListener\|ArrayBuffer\(\|Int32Array\|window\.stop\|ArrayBufferView", flags=2)
        patternT2 = re.compile("")

        if re.search(patternT1, payloadToBeChecked):
            print("Alert!!!\t", "BROWSER-FIREFOX Mozilla Firefox 17 onreadystatechange memory corruption attempt")
        if re.search(patternT2, payloadToBeChecked):
            print("Alert!!!\t", "")