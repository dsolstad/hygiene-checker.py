## hcheck.py
A passive tool, presented as an API, to check for weaknesses in configurations. It returns a JSON object where if "status" is 0, it is a pass, 2 equals failed and 1 is not properly configured.

## Requirements
$ pip3 install dnspython

## Current checks
### HTTP 
* Headers
* Subresource integrity
* Redirect to HTTPS
* Same-Site-Origin misconfigurations

### Domain
* CAA
* DNSSEC
* Zone transfer

### Email
* SPF
* DMARC

### Crypto
* TLS versions
* OCSP stapling
* RSA key strength
