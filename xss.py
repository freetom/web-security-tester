import requests
import copy
from urlparse import *
from xss_hints import *

import re

class XSS:
    requests=[]
    GET_params={}
    GET_hints={}
    POST_params={}
    reached_id=0
    s=None
    inj1='<js>'
    def __init__(self,reqs):
        self.requests= copy.deepcopy(reqs)
        skip=False  # to skip the headers . . . because every
        for request in self.requests:
            if skip:
                skip=False
                continue
            self.GET_params[request['requestId']]=parse_qs(urlparse(request['url']).query)
            if request['method']=='POST':
                self.POST_params[request['requestId']]=request['requestBody']
            skip=True

    def estimate_effort(self):
        requests=0
        old_max=0
        i=0
        while i<len(self.requests):
            requests+=len(self.GET_params[self.requests[i]['requestId']])
            if self.requests[i]['method']=="POST":
                requests+=len(self.POST_params[self.requests[i]['requestId']])+old_max
            old_max=requests
            i+=2
        requests+=len(self.requests)/2 #count also the requests needed to probe
        #   divide by two because every request is two elements (params and headers)
        print "Exactly "+str(requests)+" needed to fuzz.."

    def fuzz(self):
        self.estimate_effort()
        self.probe()    #probe normally to get hints on possible injections
        return
        skip=False
        for request in self.requests:
            if skip:
                skip=False
                continue
            self.reached_id=int(request['requestId'])
            print request['url']+' '+request['method']
            if request['method']=='GET':
                for param in self.GET_params[request['requestId']]:
                    self.test('GET',request['url'],param,request['requestId'])
                #print s.get(requests[i]['url']).text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        #print param
                        self.test('POST',request['url'],param,request['requestId'],request['requestBody'])
                        #print s.post(requests[i]['url'],requests=requests[i]['requestBody']).text.encode('utf-8')
            skip=True

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
        i=0
        while i<len(self.requests):
            if self.requests[i]['method']=='GET':
                response=s.get(self.requests[i]['url']).text.encode('utf-8')
                for param in parse_qs(urlparse(self.requests[i]['url']).query):
                    self.GET_hints[self.requests[i]['requestId']]=parseXSS(response,XSS.parseGETVal(self.requests[i]['url'],param))
            i+=2    #skip headers
        for hint in self.GET_hints:
            if self.GET_hints[hint]!=1:
                print 'got hint'

    # sends genuine requests till the request we are fuzzing (to have the original "session-state")
    def catchUp(self, s):
        i=0
        #print "len: "+str(len(self.requests))
        while int(request['requestId'])<self.reached_id:
            if request['method']=='GET':
                response= s.get(request['url']).text.encode('utf-8')
                XSS.verify(response)
            elif request['method']=='POST':
                response= s.post(request['url'],params=request['requestBody']).text.encode('utf-8')
                XSS.verify(response)
            i+=2
            #print i

    @staticmethod
    def verify(response):
        if XSS.inj1 in response:
            print "XSS found !!"
            return True
        return False

    def test(self, method, url, requestId, param,postData=None):
        s = requests.Session()
        if method=='GET':
            #res=s.get(url)
            #text=res.text.encode('utf-8')
            if GET_hints[requestId]==Hints.NONE:
                newUrl = XSS.substParam(url,param,XSS.inj1)
            self.catchUp(s)
            response = s.get(newUrl,verify=False).text.encode('utf-8')
            if XSS.verify(response):
                print "PARAM: "+param

            """print "##################"
            print newUrl
            print "##################"
            print param"""
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=XSS.inj1
            self.catchUp(s)
            response = s.post(url,params=newPost).text.encode('utf-8')
            XSS.verify(response)
            print "##################"
            print newPost
            print "##################"
