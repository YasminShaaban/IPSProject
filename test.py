import re

print ("\x0F")
print ("\(DESCRIPTION=\(CONNECT_DATA=\(SERVICE_NAME=")

patternT8 = re.compile("\\x2B", flags=2)

if re.search(patternT8, "+"):
    print "good"
