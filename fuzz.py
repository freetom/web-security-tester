import requests
import copy
from urlparse import *
from hints import *
from time import sleep
import re

from xss import XSS
from sqli import SQLI
from xxe import XXE
from open_redirect import OpenRedirect

# This class fuzzes web applications by mutating parameters of genuine requests
# The goal is to have an extensive mechanism to thoroughly test for standard vulnerabilities
#
class Fuzz:
    requestWaitTime=0.1 # seconds   -   used to prevent overloading of servers
    keepHeaders={'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language'}
    headers={}  # all the resulting filtered headers per each request
    requests=[] # all the requests
    responses=[]
    necessaryRequests={} # map requestId -> boolean to memorize if it's a required request
    lenNecessaryRequests=None
    GET_params={}
    GET_hints={}    # contains the hints that the fuzzer got to test attacks on specific GET_params
    POST_params={}
    POST_hints={}
    COOKIE_hints={}
    HEADER_hints={}
    reached_id=0    # the fuzzer walks through all the requests and keep the reached_id as reference

    # if a url points to a path in which the file has one of these extensions, then the request will be ignored
    # probably this mechanism is not good enough, especially if the backend has custom configuration
    # but still it should be useful to skip unnecessary requests (that don't trigger bugs)
    ignored_extensions={'jpg', 'jpeg', 'mp3', 'mp4', 'png', 'tiff', 'bmp', 'wav', 'ogg', 'ico', 'avi', 'html', 'js'}

    xss = None  #   ref to instance of XSS class, to test for XSS
    sqli = None #   ref to instance of SQLI class, to test for SQLI
    xxe = None  #   ref to instance of XXE class, to test for XXE
    open_redirect = None

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
            return None
        sleep(Fuzz.requestWaitTime)
        self.put_headers(s,requestId)
        if method=='GET':
            return s.get(url)
        elif method=='POST':
            return s.post(url, params=post)
        else:
            raise ValueError('Unsupported method: '+method)
        return None

    def __init__(self, reqs, headers, responses, xss, sqli, xxe, open_redirect):
        self.requests= copy.deepcopy(reqs)
        self.responses = copy.deepcopy(responses)

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
        if open_redirect:
            self.open_redirect = OpenRedirect(self)

    def estimate_effort(self):
        total=0
        if self.xss:
            total+=self.xss.estimate_effort()
        if self.sqli:
            total+=self.sqli.estimate_effort()
        if self.xxe:
            total+=self.xxe.estimate_effort()
        if self.open_redirect:
            total+=self.open_redirect.estimate_effort()

        #total+=len(self.requests) #count also the requests needed to probe
        print "Exactly "+str(total)+" requests needed to fuzz.."

    def fuzz(self):
        self.probe_offline()    #probe normally to get hints on possible injections
        self.estimate_effort()

        for request in self.requests:
            self.reached_id=int(request['requestId'])
            print request['url']+' '+request['method']
            if request['method']=='GET':
                for param in self.GET_params[request['requestId']]:
                    if self.xss:
                        self.xss.test('GET',request['url'],request['requestId'],param)
                    if self.sqli:
                        self.sqli.test('GET',request['url'],request['requestId'],param)
                    if self.xxe:
                        self.xxe.test('GET',request['url'],request['requestId'],param)
                    if self.open_redirect:
                        self.open_redirect.test('GET',request['url'],request['requestId'],param)

                #print self.send_req(requests[i]['requestId'], s, requests[i]['url'], 'GET').text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        if self.xss:
                            self.xss.test('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.sqli:
                            self.sqli.test('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.xxe:
                            self.xxe.test('POST',request['url'],request['requestId'],param,request['requestBody'])
                        if self.open_redirect:
                            self.open_redirect.test('POST',request['url'],request['requestId'],param,request['requestBody'])

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

    def get_response(self, requestId):
        for response in self.responses:
            if response['requestId']==requestId:
                return response
        raise ValueError('response with requestId: '+requestId+' not found')

    def probe_offline(self):
        print "offline-probing.."
        for request in self.requests:
            self.GET_hints[request['requestId']]={}
            self.POST_hints[request['requestId']]={}
            self.COOKIE_hints[request['requestId']]={}
            self.HEADER_hints[request['requestId']]={}
        for request in self.requests:
            if request['requestId'] not in self.necessaryRequests or self.necessaryRequests[request['requestId']]==False:
                continue
            # probe GET/POST parameters
            if request['method']=='GET':
                r=self.get_response(request['requestId'])
                if 'httpResponse' not in r:
                    print request['requestId']+' has no httpResponse'
                    response=''
                else:
                    response=r['httpResponse'].encode('utf-8')

                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
            elif request['method']=='POST':
                r=self.get_response(request['requestId'])
                if 'httpResponse' not in r:
                    print request['requestId']+' has no httpResponse'
                    response=''
                else:
                    response=r['httpResponse'].encode('utf-8')

                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
                if 'formData' in request['requestBody']:
                    for param in self.POST_params[request['requestId']]['formData']:
                        self.POST_hints[request['requestId']][param]=parseFuzz(response,request['requestBody']['formData'][param])
            else:
                raise ValueError('request method '+request['method']+" yet unsupported")

            for param in self.GET_hints[request['requestId']]:
                if (self.GET_hints[request['requestId']][param]&(~1))!=0:
                    print 'got hint on param: '+param+' '
    # deprecated
    def probe(self):
        print "probing.."
        s = requests.Session()
        for request in self.requests:
            self.GET_hints[request['requestId']]={}
            self.POST_hints[request['requestId']]={}
            self.COOKIE_hints[request['requestId']]={}
            self.HEADER_hints[request['requestId']]={}
        for request in self.requests:
            if request['requestId'] not in self.necessaryRequests or self.necessaryRequests[request['requestId']]==False:
                continue
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

            for param in self.GET_hints[request['requestId']]:
                if (self.GET_hints[request['requestId']][param]&(~1))!=0:
                    print 'got hint on param: '+param

    # sends genuine requests till the request we are fuzzing (to have the original "session-state")
    def catchUp(self, s):
        #print "len: "+str(len(self.requests))
        for request in self.requests:
            if int(request['requestId'])<self.reached_id:
                if request['method']=='GET':
                    response = self.send_req(request['requestId'], s,request['url'], 'GET').text.encode('utf-8')
                elif request['method']=='POST':
                    response = self.send_req(request['requestId'], s,request['url'], 'POST', post = request['requestBody']).text.encode('utf-8')
                XSS.verify(response)
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
            XSS.verify(response)
            i+=1
