# hcheck.py
A passive tool, presented as an API, to check for weaknesses in configurations on a domain. It outputs a JSON, where if "status" is 0, it is a pass, 2 equals failed and 1 is not properly configured.

## Requirements
$ pip3 install dnspython

## Current checks
### HTTP 
* Headers
* Cookies
* Subresource integrity
* Redirect to HTTPS
* Same-Origin-Policy misconfigurations

### Domain
* CAA
* DNSSEC
* Zone transfer

### Crypto
* TLS versions
* OCSP stapling
* RSA key strength

### Email
* SPF
* DMARC
