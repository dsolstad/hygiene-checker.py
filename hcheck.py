#!/bin/env python3
# ./hcheck.py <domain> | python3 -m json.tool

import urllib.parse
import urllib.request
import dns.resolver
import socket
import subprocess
import json
import sys
import os
import re

# status: 0 = pass, 1 = not proper, 2 = fail

class hCheck(object):

    __domain = ''
    __results = {}

    def __init__(self, domain):
        self.__domain = domain


    def __parse_headers(self, raw_headers):
        headers_map = {}
        lines = raw_headers.split('\n')
        lines = list(filter(None, lines))

        for header in lines:
            pair = header.split(': ')
            key = pair.pop(0)
            val = "".join(pair)
            if key.lower() in headers_map:
                headers_map[key.lower()] = headers_map[key.lower()] + '|' + val.strip()
            else:
                headers_map[key.lower()] =  val.strip()
        return headers_map


    def __http_headers_cookies(self, value=''):
        if value == '': return
        result = {}
        result['implemented'] = value;
        result['ref'] = ''

        flags = value.lower().split('|')
        print(flags)

        result['status'] = 0
        self.__results['http_headers_cookies'] = result


    def __http_headers_hsts(self, value=''):
        result = {}
        result['name'] = 'Strict-Transport-Security'
        result['implemented'] = value;
        result['correct'] = 'max-age=31536000; includeSubDomains; preload';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        result['status'] = 0

        if result['implemented']:
            result['status'] = 1

        flags = result['implemented'].split(';')
        flags = [x.strip().lower() for x in flags]

        info = ''
        result['status'] = 0
        if 'preload' not in flags:
            info = 'Missing preload; '
            result['status'] = 1
        if 'includesubdomains' not in flags:
            info = info + 'Missing includeSubDomains; '
            result['status'] = 1
        if 'max-age=31536000' not in flags:
            info = info + 'Missing max-age or max-age set too low; '
            result['status'] = 1
        
        result['info'] = info
        self.__results['http_headers_hsts'] = result


    def __http_headers_content_type_options(self, value=''):
        result = {}
        result['name'] = 'X-Content-Type-Options'
        result['implemented'] = value;
        result['correct'] = 'nosniff';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'

        if result['implemented']:
            result['status'] = 1
            if result['implemented'] == result['correct']:
                result['status'] = 0
        self.__results['http_headers_content_type_options'] = result


    def __http_headers_referrer_policy(self, value=''):
        result = {}
        result['name'] = 'Referrer-Policy'
        result['implemented'] = value;
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'

        if result['implemented']:
            result['status'] = 1
            value = value.lower()
            if value == 'no-referrer' or value == 'strict-origin' or value == 'strict-origin-when-cross-origin':
                result['status'] = 0
        self.__results['http_headers_referrer_policy'] = result


    def __http_headers_frame_options(self, value=''):
        result = {}
        result['name'] = 'X-Frame-Options'
        result['implemented'] = value;
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'

        if result['implemented']:
            result['status'] = 1
            value = value.lower()
            if value == 'deny' or value == 'sameorigin' or value.find('allow-from') != -1:
                result['status'] = 0
        self.__results['http_headers_frame_options'] = result


    def __http_headers_xss_protection(self, value=''):
        result = {}
        result['name'] = 'X-XSS-Protection'
        result['implemented'] = value;
        result['correct'] = '1; mode=block';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'

        if result['implemented']:
            result['status'] = 1
            if re.search('1;\s?mode=block', result['implemented']):
                result['status'] = 0
        self.__results['http_headers_xss_protection'] = result


    def __http_same_origin_policy_ajax(self, value=''):
        result = {}
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
        result['status'] = 0
        if value == '*':
            result['status'] = 2
        self.__results['http_same_origin_policy_ajax'] = result


    def __http_same_origin_policy_flash(self):
        result = {}
        result['ref'] = 'https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html'
        result['status'] = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/crossdomain.xml')
        except:
            self.__results['http_same_origin_policy_flash'] = result
            return
        if re.search('<allow-access-from domain="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 2
        self.__results['http_same_origin_policy_flash'] = result


    def __http_same_origin_policy_silverlight(self):
        result = {}
        result['ref'] = 'https://docs.microsoft.com/en-us/previous-versions/windows/silverlight/dotnet-windows-silverlight/cc197955(v=vs.95)?redirectedfrom=MSDN'
        result['status'] = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/clientaccesspolicy.xml')
        except:
            self.__results['http_same_origin_policy_silverlight'] = result
            return
        if re.search('<domain uri="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 2
        self.__results['http_same_origin_policy_silverlight'] = result


    def http_headers(self):
        f = None
        try:
            f = urllib.request.urlopen('https://' + self.__domain)
        except: return
        raw_headers = str(f.info())
        headers = self.__parse_headers(raw_headers)
        self.__http_headers_xss_protection(headers['x-xss-protection'] if 'x-xss-protection' in headers else '')
        self.__http_headers_content_type_options(headers['x-content-type-options'] if 'x-content-type-options' in headers else '')
        self.__http_headers_hsts(headers['strict-transport-security'] if 'strict-transport-security' in headers else '')
        self.__http_headers_frame_options(headers['x-frame-options'] if 'x-frame-options' in headers else '')
        self.__http_headers_referrer_policy(headers['referrer-policy'] if 'referrer-policy' in headers else '')
        self.__http_headers_cookies(headers['set-cookie'] if 'set-cookie' in headers else '')
        self.__http_same_origin_policy_ajax(headers['access-control-allow-origin'] if 'access-control-allow-origin' in headers else '')
        

    def http_redirect_to_https(self):
        status = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain).geturl()
        except:
            self.__results['http_check_redirect'] = {'status': status}
            return
        if url[0:5] != 'https':
             status = 2
        self.__results['http_check_redirect'] = {'status': status}


    def http_same_origin_policy(self):
        self.__http_same_origin_policy_flash()
        self.__http_same_origin_policy_silverlight()


    def email_spf(self):
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "TXT")
        except:
            self.__results['email_check_spf'] = {'status': 2}
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('[~|-]all', buf, re.M):
            self.__results['email_check_spf'] = {'status': 0}
        else:
            self.__results['email_check_spf'] = {'status': 2}


    def email_dmarc(self):
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query('_dmarc.' + self.__domain, "TXT")
        except:
            self.__results['email_check_dmarc'] = {'status': 2}
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('p=none', buf, re.M):
            self.__results['email_check_dmarc'] = {'status': 2}
        else:
            self.__results['email_check_dmarc'] = {'status': 0}


    def domain_caa(self):
        result = {}
        result['ref'] = 'https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization'
        result['status'] = 2
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "CAA")
        except:
            self.__results['domain_caa'] = result
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('issue ".*"', buf, re.M):
            result['status'] = 0
        self.__results['domain_caa'] = result


    def ssl_versions(self):
        depricated = ['tls1', 'tls1_1']
        for version in depricated:
            quit = subprocess.Popen(['echo', 'Q'], stdout=subprocess.PIPE)
            cmd = ['openssl', 's_client', '-' + version, '-connect', self.__domain, '-port', '443']
            try:
                output = subprocess.check_output(cmd, stdin=quit.stdout, stderr=subprocess.DEVNULL)
            except Exception as e:
                output = e.output
            if re.search('New, \(NONE\), Cipher is \(NONE\)', output.decode(), re.M):
                self.__results['ssl_support_' + version] = {'status': 0}
            else:
                self.__results['ssl_support_' + version] = {'status': 2}


    def print_results(self):
        print (json.dumps(self.__results))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('./check.py <domain>')
        sys.exit()
    check = hCheck(sys.argv[1])
    check.ssl_versions()
    check.http_redirect_to_https()
    check.http_headers()
    check.http_same_origin_policy()
    check.domain_caa()
    #check.domain_dnssec()
    check.email_spf()
    check.email_dmarc()
    check.print_results()

# TODO
# DNSSEC
# cookies
# http cache
# http expect-ct
# sub-resource integrity
# CSP
# Certificate, self-signed, weak cipers, weak key strength, stapling etc



