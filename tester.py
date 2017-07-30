import json
import sys

from fuzz import Fuzz

# should test for XSS,SQLI,open-redirect
if len(sys.argv) < 3:
    sys.exit('Usage: %s input_trace input_headers' % sys.argv[0])

with open(sys.argv[1]) as data_file:
    data = json.load(data_file)
with open(sys.argv[2]) as data_file:
    headers = json.load(data_file)

#pprint(data)

fuzz=Fuzz(data, headers)
fuzz.fuzz()
