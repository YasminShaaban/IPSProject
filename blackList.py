import re


class blackList:
    def checkBlackListTCP(payloadToBeChecked):
        patternT1 = re.compile("User-Agent\\x3A SAH Agent", flags=2)
        patternT2 = re.compile("User-Agent\\x3A Async HTTP Agent", flags=2)
        patternT3 = re.compile("malware", flags=2)
        patternT4 = re.compile("User-Agent\\x3A Tear Application", flags=2)
        patternT5 = re.compile("User-Agent\\x3A TCYWinHTTPDownload", flags=2)
        patternT6 = re.compile("\/inst\.php\?fff=", flags=2)
        patternT7 = re.compile("\/tongji\.js", flags=2)
        patternT8 = re.compile("User-Agent\\x3A ErrCode", flags=2)
        patternT9 = re.compile("User-Agent\\x3A RookIE\/1\.0\\x0D\\x0A", flags=2)
        patternT10 = re.compile("User-Agent\\x3A SelectRebates", flags=2)
        patternT11 = re.compile("User-Agent\\x3A\\x20wget\\x20\\x33\\x2E\\x30\\x0D\\x0A", flags=2)
        patternT12 = re.compile("User-Agent\\x3A\\x20Error\\x20Fix", flags=2)
        patternT13 = re.compile("User-Agent\\x3A\\x20STORMDDOS", flags=2)
        patternT14 = re.compile("\/config\.ini|3322\\x2Eorg", flags=2)
        patternT15 = re.compile("User-Agent\\x3A\\x20MacProtector", flags=2)
        patternT16 = re.compile( "Subject\\x3A You have received a Hallmark E-Card\!|href=\\x22http\\x3A\/\/www\.hallmark\.com\/",
            flags=2)
        patternT17 = re.compile("\/setup\_b\.asp\?prj=|\&pid=|\&mac=", flags=2)
        patternT18 = re.compile("\/kx4\.txt", flags=2)
        patternT19 = re.compile("\\x26\xAnSSip=", flags=2)
        patternT20 = re.compile("\/VertexNet\/tasks\.php\?uid=\\x7B", flags=2)
        patternT21 = re.compile("\/r\_autoidcnt\.asp\?mer\_seq=|\&mac=", flags=2)
        patternT22 = re.compile("\.sys\.php\?getexe=", flags=2)
        patternT23 = re.compile("\/VertexNet\/adduser\.php\?uid=\\x7B", flags=2)
        patternT24 = re.compile("\/blog\/images\/3521\.jpg\?v|\&tq=", flags=2)
        patternT25 = re.compile("\/app\/\?prj=|\&pid=|\&mac=", flags=2)
        patternT26 = re.compile("\/pte\.aspx\?ver=|\&rnd=", flags=2)
        patternT27 = re.compile("\/1cup\/script\.php", flags=2)
        patternT28 = re.compile("\/install\.asp\?mac=|\&mode", flags=2)
        patternT29 = re.compile("\/vic\.aspx\?ver=|\&rnd=", flags=2)
        patternT30 = re.compile("\/games\/java\_trust\.php\?f=", flags=2)
        patternT31 = re.compile("User-Agent\\x3A\\x20xOpera\\x2F8\\x2E\\x89", flags=2)
        patternT32 = re.compile("\/160\.rar", flags=2)
        patternT33 = re.compile("\/optima\/index\.php\|uid=\|ver=", flags=2)

        if re.search(patternT1, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user agent - SAH Agent")
        if re.search(patternT2, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user agent - Async HTTP Agent")
        if re.search(patternT3, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user agent - malware")
        if re.search(patternT4, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user agent - Tear Application")
        if re.search(patternT5, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user agent TCYWinHTTPDownload")
        if re.search(patternT6, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /inst.php?fff=")
        if re.search(patternT7, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /tongji.js")
        if re.search(patternT8, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious User-Agent ErrCode - W32/Fujacks.htm")
        if re.search(patternT9, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user-agent string RookIE/1.0")
        if re.search(patternT10, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent request for known PUA user agent - SelectRebates")
        if re.search(patternT11, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious User-Agent wget 3.0")
        if re.search(patternT12, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious user-agent string ErrorFix")
        if re.search(patternT13, payloadToBeChecked):
            print("Alert!!!\t",
                  "BLACKLIST User-Agent known malicious user-agent string STORMDDOS - Backdoor.Win32.Inject.ctt")
        if re.search(patternT14, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious uri config.ini on 3322.org domain")
        if re.search(patternT15, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST User-Agent known malicious User-Agent string MacProtector")
        if re.search(patternT16, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST EMAIL known malicious email string - You have received a Hallmark E-Card")
        if re.search(patternT17, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /setup_b.asp?prj=")
        if re.search(patternT18, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /kx4.txt")
        if re.search(patternT19, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - AnSSip=")
        if re.search(patternT20, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /VertexNet/tasks.php?uid=")
        if re.search(patternT21, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /r_autoidcnt.asp?mer_seq=")
        if re.search(patternT22, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - .sys.php?getexe=")
        if re.search(patternT23, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /VertexNet/adduser.php?uid=")
        if re.search(patternT24, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /blog/images/3521.jpg?v")
        if re.search(patternT25, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /app/?prj=")
        if re.search(patternT26, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - pte.aspx?ver=")
        if re.search(patternT27, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /1cup/script.php")
        if re.search(patternT28, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /install.asp?mac=")
        if re.search(patternT29, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - vic.aspx?ver=")
        if re.search(patternT30, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /games/java_trust.php?f=")
        if re.search(patternT31, payloadToBeChecked):
            print("Alert!!!\t",
                  "BLACKLIST User-Agent known malicious user-agent string Opera/8.89 - P2P-Worm.Win32.Palevo.ddm")
        if re.search(patternT32, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - /160.rar - Win32/Morto.A")
        if re.search(patternT33, payloadToBeChecked):
            print("Alert!!!\t", "BLACKLIST URI request for known malicious URI - optima/index.php")
