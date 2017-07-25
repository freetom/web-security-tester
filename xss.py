import requests

class XSS:
    requests=[]
    reached_id=0
    s=None
    inj1='<js>'
    def __init__(self,reqs):
        requests=raw_input(reqs)
    def fuzz(self):
        i=0
        while i<len(requests):
            if requests[i]['requestId']>reached_id:
                reached_id=requests[i]['requestId']
                print requests[i]['url']+' '+requests[i]['method']
                if requests[i]['method']=='GET':
                    for param in parse_qs(urlparse(requests[i]['url']).query):
                        xss.test(param)
                    #print s.get(requests[i]['url']).text.encode('utf-8')
                elif requests[i]['method']=='POST':
                    pass #print s.post(requests[i]['url'],requests=requests[i]['requestBody']).text.encode('utf-8')
                i+=2    # 2 because we want to skip the element that contains the recorded headers
            else:
                break

    def test(param):
        print param
