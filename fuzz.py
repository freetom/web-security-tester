import requests
import copy
from urlparse import *
from hints import *
from time import sleep
import re

from xss import XSS
from sqli import SQLI
from xxe import XXE

# This class fuzzes web applications by mutating parameters of genuine requests
# The goal is to have an extensive mechanism to thoroughly test for standard vulnerabilities
#
class Fuzz:
    requestWaitTime=0.1 # seconds   -   used to prevent overloading of servers
    keepHeaders={'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language'}
    headers={}  # all the resulting filtered headers per each request
    requests=[] # all the requests
    necessaryRequests={} # map requestId -> boolean to memorize if it's a required request
    lenNecessaryRequests=None
    GET_params={}
    GET_hints={}    # contains the hints that the fuzzer got to test attacks on specific GET_params
    POST_params={}
    POST_hints={}
    COOKIE_hints={}
    HEADER_hints={}
    reached_id=0    # the fuzzer passes through all the requests and keep the reached_id as reference

    # if a url points to a path in which the file has one of these extensions, then the request will be ignored
    # probably this mechanism is not good enough, especially if the backend has custom configuration
    # but still it should be useful to skip unnecessary requests (that don't trigger bugs)
    ignored_extensions={'jpg', 'jpeg', 'mp3', 'mp4', 'png', 'tiff', 'bmp', 'wav', 'ogg', 'ico', 'avi'}

    xss = None  #   ref to instance of XSS class, to test for XSS
    sqli = None #   ref to instance of SQLI class, to test for SQLI
    xxe = None  #   ref to instance of XXE class, to test for XXE
    
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

    def __init__(self, reqs, headers, xss, sqli, xxe):
        self.requests= copy.deepcopy(reqs)

        # get params
        for request in self.requests:
            # test from url if the request is a necessary one (e.g. not static content)
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
        if xss:
            self.xss = XSS(self)
        if sqli:
            self.sqli = SQLI(self)
        if xxe:
            self.xxe = XXE(self)

    def estimate_effort(self):
        total=0
        for request in self.requests:
            if self.xss:
                for hint in self.GET_hints[request['requestId']]:
                    val = self.GET_hints[request['requestId']][hint]
                    if (not val&Hints.NOT_FOUND) and (not val&Hints.FOUND_ESCAPED):
                        if val&Hints.URL:
                            total+=len(self.requests) #count open redirect
                        total+=len(self.requests)
            if self.sqli:    # each SQL test takes as many requests as the total number of requests required multiplied by the SQL payloads
                for param in self.GET_params:
                    total+=len(SQLI.SQL_inj)*lenNecessaryRequests
                for param in self.POST_params:
                    total+=len(SQLI.SQL_inj)*lenNecessaryRequests
            if self.xxe:    # each XXE test take as many requests as the trace
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
                        self.xss.testXSS('GET',request['url'],request['requestId'],param)
                    if self.sqli:
                        self.sqli.testSQL('GET',request['url'],request['requestId'],param)
                    if self.xxe:
                        self.xxe.testXXE('GET',request['url'],request['requestId'],param)

                #print self.send_req(requests[i]['requestId'], s, requests[i]['url'], 'GET').text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        if self.xss:
                            self.xss.testXSS('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.sqli:
                            self.sqli.testSQL('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.xxe:
                            self.xxe.testXXE('POST',request['url'],request['requestId'],param,request['requestBody'])

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
                XSS.verifyXSS(response)
            else:
                break

    def tillTheEnd(self, s):
        i=0
        while i<len(self.requests) and int(self.requests[i]['requestId'])<=self.reached_id:
            i+=1

        while i<len(self.requests):
            request=self.requests[i]
            if request['method']=='GET':
                response= self.send_req(request['requestId'], s, request['url'],'GET').text.encode('utf-8')
            elif requests[i]['method']=='POST':
                response= self.send_req(request['requestId'], s, request['url'], 'POST', post = request['requestBody']).text.encode('utf-8')
            XSS.verifyXSS(response)
            i+=1
