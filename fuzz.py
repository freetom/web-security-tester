import requests
import copy
from urlparse import *
from hints import *

import re

class Fuzz:
    requests=[]
    GET_params={}
    GET_hints={}
    POST_params={}
    reached_id=0
    s=None
    inj1='<js>'
    craftUrl='http://www.ciao.com'

    def __init__(self,reqs):
        self.requests= copy.deepcopy(reqs)
        for request in self.requests:
            self.GET_params[request['requestId']]=parse_qs(urlparse(request['url']).query)
            if request['method']=='POST':
                self.POST_params[request['requestId']]=request['requestBody']

    def estimate_effort(self):
        total=0
        counter=1
        for request in self.requests:
            #params=len(self.GET_params[request['requestId']])
            #if request['method']=="POST":
                #params+=len(self.POST_params[request['requestId']])
            #total+=(params*counter)

            for hint in self.GET_hints[request['requestId']]:
                if hint!=Hints.NOT_FOUND and hint!=Hints.FOUND_ESCAPED:
                    total+=counter if counter>0 else 1
            counter+=1
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
                #print s.get(requests[i]['url']).text.encode('utf-8')
            elif request['method']=='POST':
                if 'formData' in request['requestBody']:
                    for param in request['requestBody']['formData']:
                        #print param
                        self.test('POST',request['url'],param,request['requestId'],request['requestBody'])
                        #print s.post(requests[i]['url'],requests=requests[i]['requestBody']).text.encode('utf-8')

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
                response=s.get(request['url'],verify=False).text.encode('utf-8')
                for param in self.GET_params[request['requestId']]:
                    self.GET_hints[request['requestId']][param]=parseFuzz(response,Fuzz.parseGETVal(request['url'],param))
            for hint in self.GET_hints[request['requestId']]:
                if hint!=1:
                    print 'got hint '+hint

    # sends genuine requests till the request we are fuzzing (to have the original "session-state")
    def catchUp(self, s):
        i=0
        #print "len: "+str(len(self.requests))
        for request in self.requests:
            while int(request['requestId'])<self.reached_id:
                if request['method']=='GET':
                    response= s.get(request['url'],verify=False).text.encode('utf-8')
                    Fuzz.verify(response)
                elif request['method']=='POST':
                    response= s.post(request['url'],params=request['requestBody']).text.encode('utf-8')
                    Fuzz.verify(response)
                i+=1

    def tillTheEnd(self):
        i=0
        while int(self.requests[i]['requestId'])<=self.reached_id:
            i+=1
        while i<len(requests):
            if requests[i]['method']=='GET':
                response= s.get(requests[i]['url'],verify=False).text.encode('utf-8')
                Fuzz.verify(response)
            elif requests[i]['method']=='POST':
                response= s.post(request['url'],params=request['requestBody']).text.encode('utf-8')
                Fuzz.verify(response)

    @staticmethod
    def verify(response):
        if Fuzz.inj1 in response:
            print "Fuzz found !!"
            return True
        return False

    @staticmethod
    def verifyRedirect(response):
        if len(response.history)>0:
            if Fuzz.craftUrl in response.url:
                print "FOUND OPEN REDIRECT"
                exit()

    def testOpenRedirect(self, url, param):
        #test for Open-redirect
        s=requests.Session()
        self.catchUp(s)
        newUrl = Fuzz.substParam(url,param,Fuzz.craftUrl)
        response = s.get(newUrl, verify=False)
        Fuzz.verifyRedirect(response)
        self.tillTheEnd(s) #follow the remaining requests to check for the redirect

    def test(self, method, url, requestId, param,postData=None):
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
                    self.testOpenRedirect(url, param)
                else:
                    newUrl = Fuzz.substParam(url,param,Fuzz.inj1)
            else:
                return

            self.catchUp(s)
            response = s.get(newUrl,verify=False).text.encode('utf-8')
            if Fuzz.verify(response):
                print "PARAM: "+param

            """print "##################"
            print newUrl
            print "##################"
            print param"""
        elif method=='POST':
            newPost=copy.deepcopy(postData)
            newPost['formData'][param]=Fuzz.inj1
            self.catchUp(s)
            response = s.post(url,params=newPost).text.encode('utf-8')
            Fuzz.verify(response)
            print "##################"
            print newPost
            print "##################"
