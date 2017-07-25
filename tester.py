import json
from pprint import pprint
from urlparse import urlparse, parse_qs
import sys
#local imports
from xss import XSS

if len(sys.argv) < 2:
    sys.exit('Usage: %s input_trace' % sys.argv[0])

with open(sys.argv[1]) as data_file:
    data = json.load(data_file)

#pprint(data)

i=0
while True:
    xss=XSS(data)
    xss.fuzz()
    break
