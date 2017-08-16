import requests

from hints import *
from vulnerability_class import VulnerabilityClass
from fuzz import *

class XSS(VulnerabilityClass):
    fuzz=None

    XSS_inj='<js>'
    testURL='http://www.ciao.com'

    def __init__(self, fuzz):
        self.fuzz = fuzz

    def estimate_effort(self):
        total = 0
        for request in self.fuzz.requests:
            for param in self.fuzz.GET_hints[request['requestId']]:
                if hasToBeTested(self.fuzz.GET_hints[request['requestId']][param]):
                    total+=self.fuzz.lenNecessaryRequests
            for param in self.fuzz.POST_hints[request['requestId']]:
                if hasToBeTested(self.fuzz.POST_hints[request['requestId']][param]):
                    total+=self.fuzz.lenNecessaryRequests
        print str(total)+" requests required to test for XSS"
        return total

    def get_payload(self, paramName, paramValue):
        # paramValue can be a list / workaround
        if type(paramValue) is list:
          newVal=''.join(paramValue)
        else:
          newVal=paramValue
        return str(newVal)+" "+XSS.XSS_inj+str(self.fuzz.reached_id)+paramName+XSS.XSS_inj

    @staticmethod
    def verify(response_text):
        if XSS.XSS_inj in response_text:
            print "XSS found !!"
            index=response_text.index(XSS.XSS_inj)+len(XSS.XSS_inj)
            print response_text[index:index+response_text[index:].index(XSS.XSS_inj)] #print the payload info of the XSS
            return True
        return False

    #   returns True whether a param with a certain hint has to be tested against XSS
    @staticmethod
    def hasToBeTested(hint):
        # if the param result in the HTTP response unescaped try to inject
        if hint&Hints.NOT_FOUND:
            return False
        elif not (hint&Hints.FOUND_ESCAPED):
            if hint&Hints.JS:
                print "JS  found "+param+" "+url
                exit()
            else:
                return True
        else:
            return False

    # function to test a GET parameter
    def testGET(self, method, url, requestId, param, actualMethod='GET', postData=None):
        if not XSS.hasToBeTested(self.fuzz.GET_hints[requestId][param]):
            return

        newUrl = fuzz.Fuzz.substParam(url,param,self.get_payload(param, self.fuzz.GET_params[requestId][param]))
        #print param+" "+str(hint)

        self.fuzz.catchUp(s)
        response = self.fuzz.send_req(requestId, s, newUrl, actualMethod, params=postData).text.encode('utf-8')
        XSS.verifyXSS(response)
        self.fuzz.tillTheEnd(s)

        print "##################"
        print newUrl
        print "##################"
        print param

    def testPOST(self, method, url, requestId, param, postData):
        if not XSS.hasToBeTested(self.fuzz.POST_hints[requestId][param]):
            return

        newPost=copy.deepcopy(postData)
        newPost['formData'][param]=self.get_payload(param, postData['formData'][param])
        self.fuzz.catchUp(s)
        response = self.fuzz.send_req(requestId, s, url, 'POST', post=newPost).text.encode('utf-8')
        XSS.verifyXSS(response)
        self.fuzz.tillTheEnd(s)

        print "##################"
        print newPost
        print "##################"

    # function to test a certain request and a certain parameter
    #   method indicates which type of param is param
    #   actualMethod indicates the actual type of the request
    #   the previous clarification is needed to test GET parameters of POST requests
    def test(self, method, url, requestId, param, postData=None, actualMethod=None):
        assert not (method=='GET' and actualMethod==None)
        s = requests.Session()
        if method=='GET':
            self.testGET(method, url, requestId, param, actualMethod, postData)
        elif method=='POST':
            self.testGET(method, url, requestId, param, postData)
