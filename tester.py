import json
import sys

from fuzz import Fuzz

# should test for XSS,SQLI,open-redirect
if len(sys.argv) < 3:
    sys.exit('Usage: %s input_trace input_headers [--sqli] [--xss] [--xee]' % sys.argv[0])

if len(sys.argv) < 4:
    sys.exit('You have to provide at least a testing option ( --xss, --sqli, --xxe)')

xss=False
sqli=False
xxe=False
i=3
while i<len(sys.argv):
    if sys.argv[i]=='--xss':
        xss=True
    elif sys.argv[i]=='--sqli':
        sqli=True
    elif sys.argv[i]=='--xxe':
        xxe=True
    i+=1

with open(sys.argv[1]) as data_file:
    data = json.load(data_file)
with open(sys.argv[2]) as data_file:
    headers = json.load(data_file)

#pprint(data)

fuzz=Fuzz(data, headers, xss, sqli, xxe)
fuzz.fuzz()
