# web-security-tester
grey-box semi-automated tester for web backends

## Raison d'être
Typical bugs in web applications result in unauthorized read/write acces to data as well as unauthorized control of the server machine. Developers should be aware of standard security practices of the language they are using to prevent security flaws. To find bugs there are mainly two ways: reviewing the code or testing. Manual testing is time expensive while reviewing code isn't always possible. Manual testing might require repetitive tasks to extensively assert that the code base is secure, especially if the source is not available. Code reviews, other than being not always possible might be a real hassle if the code has been badly written.

This software is a grey-box, semi-automated tester for standard classes of web vulnerabilities such as: XSS, SQLI, open redirects, XXE, etc. The ideal solution would substitute the operation of manually testing by automating the research of several classes of vulnerabilities with good chances.

## Scheme
The tester is based on reproducing web traces from [web-tracker](https://github.com/freetom/web-tracker/)

Is a mutative based tester that first get hints (by analysing servers' responses) on how some parameters might be actually exploited to accomplish a possible standard attack and then it inject them and verify if it succeeded!

## Approach

By default the tester inject simple and not harmful payloads to just test if it is possible to exploit such mechanism to violate security but without actually harming users or systems. Therefore, the tester will produce a number of requests based on the test cases it decides to run. The number of requests might be huge and the server might suffer the traffic depending on its performances. Such scenarios should be prevented by aborting tests with too many requests and/or increasing the `requestWaitTime` in [fuzz.py](https://github.com/freetom/web-tester/blob/master/fuzz.py)

## TODO

The tester at the moment supports XSS, open redirects, SQLI, XXE. However, more cases has to be tested, especially for SQLI and better interpretation of the server response. XSS atm doesn't support injections in cookies or headers. Furthermore, other classes of vulnerabilities should become supported as well (regarding files and cmd injections).

Code has to be refactored. Bypassing of CSRF tokens has to be implemented. Can't emulate traces with the old CSRF tokens.


## Contributing

Feel free to contribute. Needs for testing, ideas, developing
