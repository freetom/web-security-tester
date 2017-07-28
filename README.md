# web-tester
semi automated testing of web backends

## Raison d'être
Bugs exist in web applications. There are mainly two ways to find them: reviewing the code or testing. Manual testing is expensive and takes time while reviewing code isn't always possible.

This software aims at testing for standard classes of web vulnerabilities such as: XSS, SQLI, open redirects, etc

## Scheme
The tester is based on reproducing web traces from [web-tracker](https://github.com/freetom/web-tracker/)

Is a mutative based tester that first get hints on how some parameters might be actually exploited to accomplish a possible standard attack and then it tests them!

## Contributing

Feel free to contribute. Needs for testing, ideas, developing
