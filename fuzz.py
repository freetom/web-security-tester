import requests
import copy
from urlparse import *
from hints import *
from time import sleep
import re

class Fuzz:
    requestWaitTime=0.1 # seconds   -   used to prevent overloading of servers
    keepHeaders={'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language'}
    headers={}
    requests=[]
    GET_params={}
    GET_hints={}
    POST_params={}
    reached_id=0
    s=None
    XSS_inj='<js>'
    craftUrl='http://www.ciao.com'

    def get_XSS_payload(self, paramName):
        return Fuzz.XSS_inj+str(self.reached_id)+paramName+Fuzz.XSS_inj

    def put_headers(self, s, requestId):
        s.headers.update(self.headers[requestId])
        #print self.headers[requestId]

    def send_req(self, requestId, s, url, method, post=None):
        sleep(Fuzz.requestWaitTime)
        self.put_headers(s,requestId)
        if method=='GET':
            return s.get(url,verify=False)
        elif method=='POST':
            return s.post(url, params=post, verify=False)
        return None

    def __init__(self, reqs, headers):
        self.requests= copy.deepcopy(reqs)

        # get params
        for request in self.requests:
            self.GET_params[request['requestId']]=parse_qs(urlparse(request['url']).query)
            if request['method']=='POST':
                self.POST_params[request['requestId']]=request['requestBody']

        # filter headers
        self.headers={}
        for header in headers:
            self.headers[header['requestId']]={}
            for requestHeaders in header['requestHeaders']:
                if requestHeaders['name'] in Fuzz.keepHeaders:
                    self.headers[header['requestId']][requestHeaders['name']]=requestHeaders['value']


    def estimate_effort(self):
        total=0
        for request in self.requests:
            #params=len(self.GET_params[request['requestId']])
            #if request['method']=="POST":
                #params+=len(self.POST_params[request['requestId']])
            #total+=(params*counter)

            for hint in self.GET_hints[request['requestId']]:
                if hint!=Hints.NOT_FOUND and hint!=Hints.FOUND_ESCAPED:
                    if hint==Hints.URL:
                        total+=len(self.requests) #count open redirect
                    total+=len(self.requests)
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
                    self.test('GET',request['url'],request['requestId'],param)
                #print self.send_req(requests[i]['requestId'], s, requests[i]['url'], 'GET').text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        #print param
                        self.test('POST',request['url'],request['requestId'],param,request['requestBody'])
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
        for request in self.requests:
            if request['method']=='GET':
                response=self.send_req(request['requestId'], s, request['url'], 'GET').text.encode('utf-8')
                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
            for hint in self.GET_hints[request['requestId']]:
                if hint!=1:
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
                Fuzz.verify(response)
            else:
                break

    def tillTheEnd(self):
        i=0
        while int(self.requests[i]['requestId'])<=self.reached_id:
            i+=1
        while i<len(requests):
            request=self.requests[i]
            if request['method']=='GET':
                response= self.send_req(request['requestId'], s, request['url'],'GET').text.encode('utf-8')
            elif requests[i]['method']=='POST':
                response= self.send_req(request['requestId'], s, request['url'], 'POST', post = request['requestBody']).text.encode('utf-8')
            Fuzz.verify(response)

    @staticmethod
    def verify(response):
        if Fuzz.XSS_inj in response:
            print "Fuzz found !!"
            index=response.index(Fuzz.XSS_inj)+len(Fuzz.XSS_inj)
            print response[index:index+response[index:].index(Fuzz.XSS_inj)] #print the payload info of the XSS
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

    def test(self, method, url, requestId, param, postData=None):
        s = requests.Session()
        if method=='GET':
            # if the param result in the text unescaped try to inject
            #print param
            hint = self.GET_hints[requestId][param]
            if hint==Hints.NOT_FOUND:
                return
            elif hint!=Hints.FOUND_ESCAPED:
                if hint==Hints.JS:
                    print "JS  found "+param+" "+url
                    exit()
                if hint==Hints.URL:
                    print "FOUND URL"
                    self.testOpenRedirect(url, param, 'GET', requestId)
                else:
                    newUrl = Fuzz.substParam(url,param,self.get_XSS_payload(param))
            else:
                return

            self.catchUp(s)
            response = self.send_req(requestId, s, newUrl, 'GET').text.encode('utf-8')
            if Fuzz.verify(response):
                print "PARAM: "+param

            print "##################"
            print newUrl
            print "##################"
            print param
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=self.get_XSS_payload(param)
            self.catchUp(s)
            response = self.send_req(requestId, s, url, 'POST', post=newPost).text.encode('utf-8')
            Fuzz.verify(response)
            print "##################"
            print newPost
            print "##################"
