from enum import Enum
import html
from urlparse import urlparse
import re

# XSS hints for the injection of a parameter
class Hints():
  NOT_FOUND =       0x1
  FOUND_ESCAPED =   0x2
  FOUND =           0x4
  JS    =           0x8
  TAG   =           0x10
  URL   =           0x20
  FILE  =           0x40
  XML   =           0x80

# is the param in the page  ? if yes, where ?
def parseFuzz(httpResponse, paramValue):
    if paramValue=='':
        return Hints.NOT_FOUND
    ret = 0x0
    if urlparse(paramValue).netloc!='':
        ret |= Hints.URL
    if re.search('<.*>', paramValue):
        ret |= Hints.XML
    try:
        originalIndex=httpResponse.index(paramValue)
        #check if it's into a script
        index1=originalIndex
        while index1<len(httpResponse):
            if (httpResponse[index1]=='<'):
                if index1+len('</script>')<=len(httpResponse):
                    if httpResponse[index1:index1+len('</script>')]=='</script>':
                        index1=originalIndex
                        while index1>=0:
                            if httpResponse[index1:index1+len('<script>')]=='<script>':
                                ret |= JS
                            index1-=1
                if index1+len('<script>')<=len(httpResponse) and httpResponse[index1:index1+len('<script>')]=='<script>':
                    break
            index1+=1
        # check if it's in a HTML tag
        index2=originalIndex
        while index2<len(httpResponse) and (httpResponse[index2]!='>' or httpResponse[index2]!='<'):
            index2+=1
        if index2<len:
            if httpResponse[index2]!='<':
                ret |=  Hints.TAG

        ret |= Hints.FOUND
        return ret
    except:
        # check if it has been escaped
        paramValue=html.escape(paramValue)
        try:
            httpResponse.index(paramValue)
            ret |= FOUND_ESCAPED
        except:
            ret |= Hints.NOT_FOUND
        return ret
