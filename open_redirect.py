from vulnerability_class import VulnerabilityClass

class OpenRedirect(VulnerabilityClass):
    fuzz=None

    testURL='http://www.ciao.com'

    def __init__(self, fuzz):
        self.fuzz = fuzz

    @staticmethod
    def verifyRedirect(response):
        if len(response.history)>0:
            if XSS.testURL in response.url:
                print "FOUND OPEN REDIRECT"
                exit()

    def testOpenRedirect(self, url, param, method, requestId, post_=None):
        #test for Open-redirect
        s=requests.Session()
        self.fuzz.catchUp(s)
        newUrl = Fuzz.substParam(url,param,XSS.testURL)
        response = self.fuzz.send_req(requestId, s, newUrl, method)
        XSS.verifyRedirect(response)
        self.fuzz.tillTheEnd(s) #follow the remaining requests to check for the redirect

    def test(self, method, url, requestId, param, postData=None):
        s = requests.Session()
        if method=='GET':
            # if the param result in the text unescaped try to inject
            hint = self.fuzz.GET_hints[requestId][param]
            #print param+" "+str(hint)
            if hint&Hints.NOT_FOUND:
                return
            elif not (hint&Hints.FOUND_ESCAPED):
                if hint&Hints.URL:
                    print "FOUND URL"
                    self.testOpenRedirect(url, param, 'GET', requestId)

        elif method=='POST':
            pass
