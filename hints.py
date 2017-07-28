from enum import Enum
import html
from urlparse import urlparse

# XSS hints for the injection of a parameter
class Hints():
  NOT_FOUND = 1
  FOUND_ESCAPED=2
  FOUND = 3
  JS = 4
  TAG = 5
  URL=6
  FILE=7

# is the param in the page  ? if yes, where ?
def parseFuzz(httpResponse, paramValue):
    if paramValue=='':
        return Hints.NOT_FOUND
    if urlparse(paramValue).netloc!='':
        return Hints.URL
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
                                return JS
                            index1-=1
                if index1+len('<script>')<=len(httpResponse) and httpResponse[index1:index1+len('<script>')]=='<script>':
                    break
            index1+=1
        # check if it's in a HTML tag
        index2=originalIndex
        while index2<len(httpResponse) and (httpResponse[index2]!='>' or httpResponse[index2]!='<'):
            index2+=1
        if index2<len:
            if httpResponse[index2]=='<':
                return Hints.FOUND
            else:
                return Hints.TAG

        return Hints.FOUND
    except:
        # check if it has been escaped
        paramValue=html.escape(paramValue)
        try:
            httpResponse.index(paramValue)
            return FOUND_ESCAPED

        except:
            return Hints.NOT_FOUND
