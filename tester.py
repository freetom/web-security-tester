import json
import sys

from fuzz import Fuzz

# should test for XSS,SQLI,open-redirect
if len(sys.argv) < 2:
    sys.exit('Usage: %s input_trace' % sys.argv[0])

with open(sys.argv[1]) as data_file:
    data = json.load(data_file)

#pprint(data)

fuzz=Fuzz(data)
fuzz.fuzz()
