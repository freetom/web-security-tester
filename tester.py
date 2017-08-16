import json
import sys
import os.path

from fuzz import Fuzz

def file_exists(name):
    return os.path.isfile(name)

# should test for XSS,SQLI,open-redirect
if len(sys.argv) < 4 or (not file_exists(sys.argv[1])) or (not file_exists(sys.argv[2])) or (not file_exists(sys.argv[3])):
    sys.exit('Usage: %s <requests_file> <headers_file> <responses_file>  [--sqli] [--xss] [--xxe] [--open-redirect]' % sys.argv[0])

if len(sys.argv) < 5:
    sys.exit('You have to provide at least one testing option ( --xss, --sqli, --xxe, --open-redirect)')

xss=False
sqli=False
xxe=False
open_redirect=False
i=3
while i<len(sys.argv):
    if sys.argv[i]=='--xss':
        xss=True
    elif sys.argv[i]=='--sqli':
        sqli=True
    elif sys.argv[i]=='--xxe':
        xxe=True
    elif sys.argv[i]=='--open-redirect':
        open_redirect=True
    i+=1

with open(sys.argv[1]) as data_file:
    data = json.load(data_file)
with open(sys.argv[2]) as data_file:
    headers = json.load(data_file)
with open(sys.argv[3]) as data_file:
    responses = json.load(data_file)

#pprint(data)

fuzz=Fuzz(data, headers, responses, xss, sqli, xxe, open_redirect)
fuzz.fuzz()
