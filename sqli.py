import requests

from hints import *
from vulnerability_class import VulnerabilityClass

class SQLI(VulnerabilityClass):
    fuzz = None

    SQL_inj={'1\'; sleep(3)--', '1; sleep(3)--', '1\'); sleep(3)--', '1); sleep(3)--'}

    def __init__(self, fuzz):
        self.fuzz = fuzz

    def estimate_effort(self):
        # each SQL test takes as many requests as the total number of requests required multiplied by the SQL payloads
        total=0
        for request in self.fuzz.requests:
            for param in self.fuzz.GET_params:
                total+=len(SQLI.SQL_inj)*lenNecessaryRequests
            for param in self.fuzz.POST_params:
                total+=len(SQLI.SQL_inj)*lenNecessaryRequests
        return total

    def get_payload(self, index):
        if index<0 or index>=len(SQLI.SQL_inj):
            raise ValueError('index not in range of SQL_inj')
        return SQL_inj[index]

    def verify(self, response, param, requestId):
        if response.status_code>=500:
            print "Potential SQLI in "+param+" id:"+requestId
            return True
        elif response.elapsed.total_seconds()>=3:
            print "Successful SQLI in "+param+" id:"+requestId
            return True
        else:
            try:
                pass
                #should test for SQL error messages in response
                #if re.search('SQL|error', response.text)!=None:
                #    print "SQL error shown in page"
            except:
                pass
            return False

    # for each test, try each injection string and verify
    def test(self, method, url, requestId, param, postData=None):
        s=requests.Session()
        if method=='GET':
            for i in range(len(SQLI.SQL_inj)):
                newUrl = Fuzz.substParam(url,param,self.get_SQL_payload(i))
                self.fuzz.catchUp(s)
                print "Attempting GET SQLI on "+param
                response = self.fuzz.send_req(requestId, s, newUrl, 'GET')
                if self.verifySQL(response, param, requestId):
                    break
                self.fuzz.tillTheEnd(s)
        elif method=='POST':
            for i in range(len(self.fuzz.SQL_inj)):
                newPost=copy.deepcopy(postData)
                newPost['formData'][param]=self.get_SQL_payload(i)
                self.fuzz.catchUp(s)
                print "Attempting GET SQLI on "+param
                response = self.fuzz.send_req(requestId, s, url, 'POST', post=newPost)
                if self.verifySQL(response, param, requestId):
                    break
                self.fuzz.tillTheEnd(s)
