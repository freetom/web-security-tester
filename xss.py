import requests
import copy
from urlparse import *
import re

class XSS:
    requests=[]
    reached_id=0
    s=None
    inj1='<js>'
    def __init__(self,reqs):
        self.requests= copy.deepcopy(reqs)
    def fuzz(self):
        i=0
        while i<len(self.requests):
            if self.requests[i]['requestId']>self.reached_id:
                self.reached_id=self.requests[i]['requestId']
                print self.requests[i]['url']+' '+self.requests[i]['method']
                if self.requests[i]['method']=='GET':
                    for param in parse_qs(urlparse(self.requests[i]['url']).query):
                        self.test('GET',self.requests[i]['url'],param)
                    #print s.get(requests[i]['url']).text.encode('utf-8')
                elif self.requests[i]['method']=='POST':
                    pass #print s.post(requests[i]['url'],requests=requests[i]['requestBody']).text.encode('utf-8')
                i+=2    # 2 because we want to skip the element that contains the recorded headers
            else:
                break

    @staticmethod
    def substParam(url,name,newValue):
        index=url.index(name+'=')
        if index!=-1:
            index+=len(name)+1
            try:
                index2=url[index:].index('&')
                if index2!=-1:
                    return url[0:index]+newValue+url[index2:]
            except:
                return url[0:index]+newValue

    def catchUp(self, s):
        i=0
        while int(self.requests[i]['requestId'])<self.reached_id:
            if self.requests[i]['method']=='GET':
                print s.get(self.requests[i]['url']).text.encode('utf-8')
            elif self.requests[i]['method']=='POST':
                print s.post(self.requests[i]['url'],requests=self.requests[i]['requestBody']).text.encode('utf-8')
            i+=1


    def test(self, method, url, param):
        s = requests.Session()
        #if method=='GET':
            #res=s.get(url)
            #text=res.text.encode('utf-8')
        newUrl = XSS.substParam(url,param,XSS.inj1)
        self.catchUp(s)
        s.get(newUrl).text.encode('utf-8')

        print "##################"
        print newUrl
        print "##################"
        #print param
