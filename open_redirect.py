import requests

from hints import *
from vulnerability_class import VulnerabilityClass
import fuzz

class OpenRedirect(VulnerabilityClass):
    fuzz=None

    testURL='https://www.ciao.com'

    def __init__(self, fuzz):
        self.fuzz = fuzz

    def estimate_effort(self):
        total=0
        for request in self.fuzz.requests:
            for param in self.fuzz.GET_hints[request['requestId']]:
                val = self.fuzz.GET_hints[request['requestId']][param]
                if val&Hints.URL:
                    total+=self.fuzz.lenNecessaryRequests #count open redirect
        print str(total)+" requests required to test for open-redirects"
        return total

    def get_payload(self):
        return OpenRedirect.testURL

    @staticmethod
    def verify(response):
        if len(response.history)>0:
            if self.get_payload() in response.url:
                print "FOUND OPEN REDIRECT"
                exit()

    def testOpenRedirect(self, url, param, method, requestId, actualMethod=None, post_=None):
        assert not (method=='GET' and actualMethod==None)
        #test for Open-redirect
        s=requests.Session()
        self.fuzz.catchUp(s)
        if method=='GET':
            newUrl = fuzz.Fuzz.substParam(url,param,self.get_payload())
            response = self.fuzz.send_req(requestId, s, newUrl, actualMethod)
        elif method=='POST':
            newPost=copy.deepcopy(post_)
            newPost['formData'][param]=self.get_payload()
            response = self.fuzz.send_req(requestId, s, url, 'POST')
        else:
            raise ValueError('method: '+method+' yet unsupported')
        OpenRedirect.verify(response)
        self.fuzz.tillTheEnd(s) #follow the remaining requests to check for the redirect

    @staticmethod
    def hasToBeTested(hint):
        if hint&Hints.URL:
            print "FOUND URL"
            return True
        return False

    def test(self, method, url, requestId, param, postData=None, actualMethod=None):
        s = requests.Session()
        if method=='GET':
            if not OpenRedirect.hasToBeTested(self.fuzz.GET_hints[requestId][param]):
                return
            self.testOpenRedirect(url, param, 'GET', requestId, actualMethod, postData)

        elif method=='POST':
            if not OpenRedirect.hasToBeTested(self.fuzz.POST_hints[requestId][param]):
                return
            self.testOpenRedirect(url, param, 'POST', requestId, post_=postData)
