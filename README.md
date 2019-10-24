# hygiene-check.py
A passive hygiene checker, presented as an API, to check for weaknesses of a domain. 

## Requirements
```
$ pip3 install dnspython
```

## Usage
```
$ python3 hygiene-checker.py <domain> | python3 -m json.tool
```

## Current checks
### HTTP 
* Headers
* Cookies
* Subresource integrity
* Redirect to HTTPS
* Same-Origin-Policy misconfigurations
* Banner grabbing

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
