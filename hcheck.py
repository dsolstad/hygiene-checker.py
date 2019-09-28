#!/bin/env python3
# ./hcheck.py <domain> | python3 -m json.tool

import urllib.parse
import urllib.request
import dns.resolver
import dns.query
import dns.zone
import socket
import subprocess
import json
import sys
import os
import re

# status: 0 = pass, 1 = not proper, 2 = fail

class hCheck(object):

    __domain = ''
    __results = {'http': {}, 'domain': {}, 'email': {}, 'crypto': {}}

    def __init__(self, domain):
        self.__domain = domain


    def domain_check(self):
        self.__domain_caa()
        self.__domain_dnssec()
        self.__domain_zone_transfer()


    def crypto_check(self):
        self.__tls_versions()


    def email_check(self):
        self.__email_spf()
        self.__email_dmarc();


    def http_check(self):
        f = None
        try:
            f = urllib.request.urlopen('https://' + self.__domain)
        except: return
        raw_headers = str(f.info())
        raw_body = f.read()
        headers = self.__parse_headers(raw_headers)

        self.__http_subresource_integrity(raw_body)
        self.__http_redirect_to_https()
        self.__http_headers_xss_protection(headers['x-xss-protection'] if 'x-xss-protection' in headers else '')
        self.__http_headers_content_type_options(headers['x-content-type-options'] if 'x-content-type-options' in headers else '')
        self.__http_headers_hsts(headers['strict-transport-security'] if 'strict-transport-security' in headers else '')
        self.__http_headers_frame_options(headers['x-frame-options'] if 'x-frame-options' in headers else '')
        self.__http_headers_referrer_policy(headers['referrer-policy'] if 'referrer-policy' in headers else '')
        self.__http_headers_cookies(headers['set-cookie'] if 'set-cookie' in headers else '')
        self.__http_headers_content_security_policy(headers['content-security-policy'] if 'content-security-policy' in headers else '')
        self.__http_same_origin_policy_ajax(headers['access-control-allow-origin'] if 'access-control-allow-origin' in headers else '')
        self.__http_same_origin_policy_flash()
        self.__http_same_origin_policy_silverlight()


    def __parse_headers(self, raw_headers):
        headers_map = {}
        lines = raw_headers.split('\n')
        lines = list(filter(None, lines))

        for header in lines:
            pair = header.split(': ')
            key = pair.pop(0)
            val = "".join(pair)
            if key.lower() in headers_map:
                headers_map[key.lower()] = headers_map[key.lower()] + '\n' + val.strip()
            else:
                headers_map[key.lower()] =  val.strip()
        return headers_map


    def __http_subresource_integrity(self, body):
        result = {}
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'
        result['status'] = 0
        result['details'] = []

        # Iterate through all script and link elements
        for resource in re.findall(r'(<(script|link).*?>)', body.decode("utf-8")):
            # Ignore link elements that is not stylesheets
            if resource[1] == 'link' and resource[0].find('stylesheet') == -1:
                continue
            # Continue only if the itengrity attribute is missing
            if resource[0].find('integrity') == -1:
                # Extract the URL
                url = re.findall(r'(src|href)="(.*?\/\/.*?)"', resource[0])
                if url:
                    result['details'].append(resource[0])
                    result['status'] = 2
        self.__results['http']['subresource_integrity'] = result


    def __http_headers_cookies(self, value=''):
        result = {}
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'
        result['status'] = 0
        result['details'] = []

        if value == '':
            result['details'] = ['No cookies found']
            self.__results['http']['headers_cookie_flags'] = result
            return

        for cookie in value.split('\n'):
            pos = cookie.find('=')
            cookie_name = cookie[0:pos]
            cookie = cookie.lower()
            
            result['status'] = 0
            if 'secure' not in cookie:
                result['details'].append(cookie_name + ': Missing secure')
            if 'httponly' not in cookie:
                result['details'].append(cookie_name + ': Missing httponly')
            if 'samesite=lax' not in cookie or 'samesite=strict' not in cookie:
                result['details'].append(cookie_name + ': Missing samesite')
            
            if len(result['details']) > 0:
                result['status'] = 2

            self.__results['http']['headers_cookie_flags'] = result


    def __http_headers_hsts(self, value=''):
        result = {}
        result['name'] = 'Strict-Transport-Security'
        result['implemented'] = value;
        result['correct'] = 'max-age=31536000; includeSubDomains; preload';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        result['status'] = 2
        result['details'] = []

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_hsts'] = result
            return

        flags = value.split(';')
        flags = [x.strip().lower() for x in flags]

        result['status'] = 0
        if 'preload' not in flags:
            result['details'].append('Missing preload')
        if 'includesubdomains' not in flags:
            result['details'].append('Missing includeSubDomains')
        if 'max-age=31536000' not in flags:
            result['details'].append('Missing max-age or max-age set too low')
        
        if len(result['details']) == 0:
            result['status'] = 0

        self.__results['http']['headers_hsts'] = result


    def __http_headers_cache_control(self, value=''):
        result = {}
        result['name'] = 'Cache-Control'
        result['implemented'] = value;
        result['correct'] = 'no-store'
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'
        result['status'] = 0
        result['details'] = []

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_cache_control'] = result
            return

        value = value.lower()
        if value != 'no-store':
            result['status'] = 2

        self.__results['http']['headers_content_security_policy'] = result


    def __http_headers_content_security_policy(self, value=''):
        result = {}
        result['name'] = 'Content-Security-Policy'
        result['implemented'] = value;
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        result['status'] = 2
        result['details'] = []

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_content_security_policy'] = result
            return

        value = value.lower()
        if value != 'unsafe-eval' and value != 'unsafe-inline':
            result['status'] = 0

        self.__results['http']['headers_content_security_policy'] = result


    def __http_headers_content_type_options(self, value=''):
        result = {}
        result['name'] = 'X-Content-Type-Options'
        result['implemented'] = value;
        result['correct'] = 'nosniff';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
        result['status'] = 2
        result['details'] = []

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_content_type_options'] = result
            return

        if result['implemented'] == result['correct']:
            result['status'] = 0

        self.__results['http']['headers_content_type_options'] = result


    def __http_headers_referrer_policy(self, value=''):
        result = {}
        result['name'] = 'Referrer-Policy'
        result['implemented'] = value;
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
        result['status'] = 2

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_referrer_policy'] = result
            return

        value = value.lower()
        if value == 'no-referrer' or value == 'strict-origin' or value == 'strict-origin-when-cross-origin':
            result['status'] = 0

        self.__results['http']['headers_referrer_policy'] = result


    def __http_headers_frame_options(self, value=''):
        result = {}
        result['name'] = 'X-Frame-Options'
        result['implemented'] = value;
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        result['status'] = 2

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_frame_options'] = result
            return

        value = value.lower()
        if value == 'deny' or value == 'sameorigin' or value.find('allow-from') != -1:
            result['status'] = 0
        self.__results['http']['headers_frame_options'] = result


    def __http_headers_xss_protection(self, value=''):
        result = {}
        result['name'] = 'X-XSS-Protection'
        result['implemented'] = value;
        result['correct'] = '1; mode=block';
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
        result['status'] = 2

        if value == '':
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_xss_protection'] = result
            return

        if re.search('1;\s?mode=block', result['implemented']):
            result['status'] = 0

        self.__results['http']['headers_xss_protection'] = result


    def __http_same_origin_policy_ajax(self, value=''):
        result = {}
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
        result['status'] = 0
        if value == '*':
            result['status'] = 2
        self.__results['http']['same_origin_policy_ajax'] = result


    def __http_same_origin_policy_flash(self):
        result = {}
        result['ref'] = 'https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html'
        result['status'] = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/crossdomain.xml')
        except:
            self.__results['http']['same_origin_policy_flash'] = result
            return
        if re.search('<allow-access-from domain="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 2
        self.__results['http']['same_origin_policy_flash'] = result


    def __http_same_origin_policy_silverlight(self):
        result = {}
        result['ref'] = 'https://docs.microsoft.com/en-us/previous-versions/windows/silverlight/dotnet-windows-silverlight/cc197955(v=vs.95)?redirectedfrom=MSDN'
        result['status'] = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/clientaccesspolicy.xml')
        except:
            self.__results['http']['same_origin_policy_silverlight'] = result
            return
        if re.search('<domain uri="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 2
        self.__results['http']['same_origin_policy_silverlight'] = result


    def __http_redirect_to_https(self):
        status = 0
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain).geturl()
        except:
            self.__results['http']['redirect_to_https'] = {'status': status}
            return
        if url[0:5] != 'https':
             status = 2
        self.__results['http']['redirect_to_https'] = {'status': status}


    def __email_spf(self):
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "TXT")
        except:
            self.__results['email']['spf'] = {'status': 2}
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('[~|-]all', buf, re.M):
            self.__results['email']['spf'] = {'status': 0}
        else:
            self.__results['email']['spf'] = {'status': 2}


    def __email_dmarc(self):
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query('_dmarc.' + self.__domain, "TXT")
        except:
            self.__results['email']['dmarc'] = {'status': 2}
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('p=none', buf, re.M):
            self.__results['email']['dmarc'] = {'status': 2}
        else:
            self.__results['email']['dmarc'] = {'status': 0}


    def __domain_caa(self):
        result = {}
        result['ref'] = 'https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization'
        result['status'] = 2
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "CAA")
        except:
            self.__results['domain']['caa'] = result
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('issue ".*"', buf, re.M):
            result['status'] = 0
        self.__results['domain']['caa'] = result


    def __domain_dnssec(self):
        result = {}
        result['ref'] = 'https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions'
        result['status'] = 2
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "DNSKEY")
        except:
            self.__results['domain']['dnssec'] = result
            return

        result['status'] = 0
        self.__results['domain']['dnssec'] = result


    def __domain_zone_transfer(self):
        result = {}
        result['ref'] = 'https://en.wikipedia.org/wiki/DNS_zone_transfer'
        result['status'] = 0

        answer = str(dns.resolver.query(self.__domain, 'NS').rrset)
        ns = answer.split("\n")[0].split(' ')[4]

        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, self.__domain))
        except:
            self.__results['domain']['zone_transfer'] = result
            return

        result['status'] = 2
        self.__results['domain']['zone_transfer'] = result

        """
        # Results
        names = z.nodes.keys()
        for n in names:
            print(z[n].to_text(n))"""


    def __tls_versions(self):
        depricated = ['tls1', 'tls1_1']
        for version in depricated:
            quit = subprocess.Popen(['echo', 'Q'], stdout=subprocess.PIPE)
            cmd = ['openssl', 's_client', '-' + version, '-connect', self.__domain, '-port', '443']
            try:
                output = subprocess.check_output(cmd, stdin=quit.stdout, stderr=subprocess.DEVNULL)
            except Exception as e:
                output = e.output
            if re.search('New, \(NONE\), Cipher is \(NONE\)', output.decode(), re.M):
                self.__results['crypto']['tls_support_' + version] = {'status': 0}
            else:
                self.__results['crypto']['tls_support_' + version] = {'status': 2}


    def print_results(self):
        print (json.dumps(self.__results))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('./hcheck.py <domain>')
        sys.exit()
    check = hCheck(sys.argv[1])
    check.crypto_check()
    check.http_check()
    check.domain_check()
    check.email_check()
    check.print_results()

# TODO
# Certificate, self-signed, weak cipers, weak key strength, stapling etc

