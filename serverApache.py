import re


class ServerApache:
    def checkServerApacheTCP(payloadToBeChecked):
        patternT1 = re.compile("\.do\?redirect\\x3A", flags=2) #webapplicationattackclass -->82
        # SERVER-APACHE Apache Struts2 blacklisted method redirect
        patternT2 = re.compile("\.do\?redirectAction\\x3A", flags=2)#webapplicationattackclass-->83
        # SERVER-APACHE Apache Struts2 blacklisted method redirect
        patternT3 = re.compile("\.action\?", flags=2) #-->94 same 8
        #SERVER-APACHE Apache Struts allowStaticMethodAccess invocation attempt
        patternT4 = re.compile("\.action\?redirect\\x3A", flags=2)#-->62
        #SERVER-APACHE Apache Struts2 blacklisted method redirect
        patternT5 = re.compile("\.action\?redirectAction\\x3A|", flags=2)#-->63
        #SERVER-APACHE Apache Struts2 blacklisted method redirectAction
        patternT6 = re.compile(".action\?", flags=2)#-->64 same 4
        #SERVER-APACHE Apache Struts arbitrary OGNL remote code execution attempt
        patternT7 = re.compile("=\$\{\{", flags=2) # -->64 same 4
        # SERVER-APACHE Apache Struts arbitrary OGNL remote code execution attempt
        patternT8 = re.compile("\(@java\.lang\.Runtime@getRuntime\(\)\)\.exec\(", flags=2)#-->65
        #SERVER-APACHE Apache Struts OGNL getRuntime.exec static method access attempt
        patternT9 = re.compile("\/\{#", flags=2)#-->66 same 5
        #SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt
        patternT10 = re.compile("/%25%7B", flags=2)
        #-->66 same 5
        #SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt
        patternT11 = re.compile("\}", flags=2)  # -->66-->67 same 5
        # SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt
        patternT12 = re.compile("\/\$\{#", flags=2)#-->67 same 5
        # SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt
        patternT13= re.compile("\.do", flags=2)#->81 same 8
        #msg: "SERVER-APACHE Apache Struts allowStaticMethodAccess invocation attempt"
        patternT14 = re.compile("allowStaticMethodAccess", flags=2)#-->81 same 8
        # msg: "SERVER-APACHE Apache Struts allowStaticMethodAccess invocation attempt"
        patternT15 = re.compile("\.action", flags=2)#-->25 same 1
        #msg: "SERVER-APACHE Apache Struts2 blacklisted method redirect"
        patternT16 = re.compile("new", flags=2) #same 1 --> 25
        #msg: "SERVER-APACHE Apache Struts2 blacklisted method redirect"
        patternT18 = re.compile("\.action\?", flags=2)#same 2-->27
       #msg:"SERVER-APACHE Apache Struts remote code execution attempt - GET parameter"
        patternT19 = re.compile("@java.lang.", flags=2) #same 2  --->27
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt - GET parameter"
        patternT20 = re.compile("\.action\?",flags=2)#same 3 --->31
       # msg"SERVER-APACHE Apache Struts remote code execution attempt - DebuggingInterceptor"
        patternT21 = re.compile("debug=command", flags=2) #same 3 --->31
        ## msg"SERVER-APACHE Apache Struts remote code execution attempt - DebuggingInterceptor"
        patternT22 = re.compile("xslt\.location=", flags=2)#-->128
        #msg: "SERVER-APACHE Apache Struts xslt.location local file inclusion attempt"
        patternT23 = re.compile("\\x23_memberAccess", flags=2)  # -->117 -->118 same 6
        #msg:"SERVER-APACHE Apache Struts remote code execution attempt"
        patternT24=re.compile("new",flags=2)#-->117  same 6
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt"
        patternT25 = re.compile("@java\.lang\.", flags=2)  # -->118  same 6
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt"
        patternT26 = re.compile("\.action\?action\\x3A \\x7B", flags=2)  # -->87 same 6
        #msg: "SERVER-APACHE Apache Struts2 remote code execution attempt"
        patternT27 = re.compile("\.start\\x28 \\x29", flags=2)  # -->87 same 6
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt"
        patternT28 = re.compile("\.action", flags=2)  # -->93   same 7
       # "SERVER-APACHE Apache Struts remote code execution attempt - CookieInterceptor"
        patternT29 = re.compile("Cookie\\x3A", flags=2)  # -->93 same 7
        # "SERVER-APACHE Apache Struts remote code execution attempt - CookieInterceptor"
        patternT30 = re.compile("\.action\?", flags=2)  # -->95 same 2
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt - GET parameter"
        patternT31 = re.compile("new", flags=2)  # -->95 same 2
        # msg:"SERVER-APACHE Apache Struts remote code execution attempt - GET parameter"

        if re.search(patternT1, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirect")
        if re.search(patternT2, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirect")
        if re.search(patternT3, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts allowStaticMethodAccess invocation attempt")
        if re.search(patternT4, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirect")
        if re.search(patternT5, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirectAction")
        if re.search(patternT6, payloadToBeChecked) and re.search(patternT7, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts arbitrary OGNL remote code execution attempt")
        if re.search(patternT8, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts OGNL getRuntime.exec static method access attempt")
        if re.search(patternT9, payloadToBeChecked) and re.search(patternT10, payloadToBeChecked)and re.search(patternT11, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt")
        if re.search(patternT11, payloadToBeChecked) and re.search(patternT12, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts wildcard matching OGNL remote code execution attempt")
        if re.search(patternT13, payloadToBeChecked) and re.search(patternT14, payloadToBeChecked):
            print("Alert!!!\t",
                  "SERVER-APACHE Apache Struts allowStaticMethodAccess invocation attempt")
        if re.search(patternT14, payloadToBeChecked) and re.search(patternT15, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirect")
        if re.search(patternT16, payloadToBeChecked) and re.search(patternT15, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 blacklisted method redirect")
        if re.search(patternT18, payloadToBeChecked) and re.search(patternT19, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt - GET parameter")
        if re.search(patternT20, payloadToBeChecked) and re.search(patternT21, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt - DebuggingInterceptor")
        if re.search(patternT22, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts xslt.location local file inclusion attempt")
        if re.search(patternT23, payloadToBeChecked) and re.search(patternT24, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt")
        if re.search(patternT25, payloadToBeChecked) and re.search(patternT23, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt")
        if re.search(patternT26, payloadToBeChecked) and re.search(patternT27, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts2 remote code execution attempt")
        if re.search(patternT28, payloadToBeChecked) and re.search(patternT29, payloadToBeChecked):
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt - CookieInterceptor")
        if re.search(patternT30, payloadToBeChecked) and re.search(patternT31, payloadToBeChecked) :
            print("Alert!!!\t", "SERVER-APACHE Apache Struts remote code execution attempt - GET parameter")

