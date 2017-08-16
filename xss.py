from vulnerability_class import VulnerabilityClass

class XSS(VulnerabilityClass):
    fuzz=None

    XSS_inj='<js>'
    testURL='http://www.ciao.com'

    def __init__(self, fuzz):
        self.fuzz = fuzz

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

    def test(self, method, url, requestId, param, postData=None):
        s = requests.Session()
        if method=='GET':
            # if the param result in the text unescaped try to inject
            hint = self.fuzz.GET_hints[requestId][param]
            #print param+" "+str(hint)
            if hint&Hints.NOT_FOUND:
                return
            elif not (hint&Hints.FOUND_ESCAPED):
                if hint&Hints.JS:
                    print "JS  found "+param+" "+url
                    exit()
                else:
                    newUrl = Fuzz.substParam(url,param,self.get_XSS_payload(param, self.fuzz.GET_params[requestId][param]))
            else:
                return

            self.fuzz.catchUp(s)
            response = self.fuzz.send_req(requestId, s, newUrl, 'GET').text.encode('utf-8')
            XSS.verifyXSS(response)
            self.fuzz.tillTheEnd(s)

            print "##################"
            print newUrl
            print "##################"
            print param
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=self.get_XSS_payload(param, postData['formData'][param])
            self.fuzz.catchUp(s)
            response = self.fuzz.send_req(requestId, s, url, 'POST', post=newPost).text.encode('utf-8')
            XSS.verifyXSS(response)
            self.fuzz.tillTheEnd(s)

            print "##################"
            print newPost
            print "##################"
