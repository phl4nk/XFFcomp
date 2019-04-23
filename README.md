# XFFcomp

A thread safe (hopefully) X-Forwarded-For header comparer. Sends a request to the url twice, one with the `X-Forwarded-For: 127.0.0.1` header, and one without. Compares the results, and saves to a file. Might be used to find bypasses within certain sites. 

### Usage

`xffcomp.py <url_file> <thread_count>`

### Example
```sh
$ ./xffcomp.py ./alexa_top_10k.txt 10
[+] Checking: https://test.com
[+] Checking: https://google.com
[+] Checking: https://github.com
[+] Checking: https://facebook.com
```
### Links
[Alexa Top 1 Million 2016](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip)
