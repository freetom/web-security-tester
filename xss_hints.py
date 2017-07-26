from enum import Enum

# XSS hints for the injection
class Hints():
  NONE = 1
  JS = 2
  TAG=3

# is the param in the page  ? if yes, where ?
def parseXSS(httpResponse, paramValue):
    if paramValue=='':
        return Hints.NONE
    try:
        originalIndex=httpResponse.index(paramValue)
        #check if it's into a script
        index1=originalIndex
        while index1<len(httpResponse):
            if (httpResponse[index1]=='<'):
                if index1+len('</script>')<=len(httpResponse):
                    if httpResponse[index1:index1+len('</script>')]=='</script>':
                        return Hints.JS
                break
            index1+=1
        # check if it's in a HTML tag
        index2=originalIndex
        while index2<len(httpResponse) and (httpResponse[index2]!='>' or httpResponse[index2]!='<'):
            index2+=1
        if index2<len:
            if httpResponse[index2]=='<':
                return Hints.NONE
            else:
                return Hints.TAG

        return Hints.NONE
    except:
        return Hints.NONE
