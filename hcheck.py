#!/bin/env python3
#
# Requirements: 
# pip3 install dnspython
# openssl
#
# ./hcheck.py <domain> | python3 -m json.tool
#

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


class hCheck(object):

    __domain = ''
    __results = {'stats': {}, 'http': {}, 'domain': {}, 'email': {}, 'crypto': {}}
    __num_failed = 0
    __num_passed = 0
    __num_misconfigured = 0
    __email_present = False
    __https_present = False
    __http = {'status': 0, 'final_url': '', 'headers': {}, 'body': ''}
    __https = {'status': 0, 'final_url': '', 'headers': {}, 'body': ''}


    def __init__(self, domain):
        self.__domain = domain


    def print_results(self):
        print (json.dumps(self.__results))


    def get_stats(self):
        self.__results['stats'] = {}

        for cat_key, cat_val in self.__results.items():
           for key, val in cat_val.items():
                if val['status'] == 'passed':
                    self.__num_passed += 1
                elif val['status'] == 'failed':
                    self.__num_failed += 1
                else:
                    self.__num_misconfigured += 1

        self.__results['stats']['failed'] = self.__num_failed
        self.__results['stats']['passed'] = self.__num_passed
        self.__results['stats']['misconfigured'] = self.__num_misconfigured
                    
    
    def check_domain(self):
        self.__domain_caa()
        self.__domain_dnssec()
        self.__domain_zone_transfer()


    def check_crypto(self):
        self.__crypto_tls_versions()
        self.__crypto_rsa_key_strength()
        self.__crypto_ocsp_stapling()


    def check_email(self):
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "MX")
        except:
            return
        self.__email_present = True
        self.__email_spf()
        self.__email_dmarc();


    def check_http(self):
        self.__get_http_response()
        self.__http_redirect_to_https()
        self.__http_subresource_integrity()
        self.__http_headers_xss_protection()
        self.__http_headers_content_type_options()
        self.__http_headers_hsts()
        self.__http_headers_frame_options()
        self.__http_headers_referrer_policy()
        self.__http_headers_cookies()
        self.__http_headers_content_security_policy()
        self.__http_headers_banner_grapping()
        self.__http_same_origin_policy_ajax()
        self.__http_same_origin_policy_flash()
        self.__http_same_origin_policy_silverlight()


    def __parse_headers(self, raw_headers):
        headers_map = {}
        lines = raw_headers.split('\n')
        lines = list(filter(None, lines))
        for header in lines:
            pair = header.split(': ')
            key = pair.pop(0)
            val = ': '.join(pair)
            if key.lower() in headers_map:
                headers_map[key.lower()] = headers_map[key.lower()] + '\n' + val.strip()
            else:
                headers_map[key.lower()] =  val.strip()
        return headers_map


    def __get_http_response(self):
        # Check to see if a http server is present at port 80
        try:
            http = urllib.request.urlopen('http://' + self.__domain)
            self.__http['status'] = http.getcode()
            self.__http['headers'] = self.__parse_headers(str(http.info()))
            self.__http['body'] = http.read().decode('utf-8')
            self.__http['final_url'] = http.geturl()
        except: pass

        # Check to see if a https server is present at port 443
        try:
            https = urllib.request.urlopen('https://' + self.__domain)
            self.__https['status'] = https.getcode()
            self.__https['headers'] = self.__parse_headers(str(https.info()))
            self.__https['body'] = https.read().decode('utf-8')
            self.__https['final_url'] = https.geturl()
        except: pass

        if self.__https['status'] == 200:
            self.__https_present = True


    def __http_redirect_to_https(self):
        result = {}
        result['status'] = 'passed'
        if self.__http['final_url'][0:5] != 'https':
             result['status'] = 'failed'
        self.__results['http']['redirect_to_https'] = result


    def __http_headers_banner_grapping(self):
        result = {}
        result['recommendation'] = "Don't disclose unnecessary bits of information about the underlying system."
        result['ref'] = ''
        result['status'] = 'passed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if headers.get('server'):
            result['details'].append('server: ' + headers.get('server'))

        if headers.get('x-powered-by'):
            result['details'].append('x-powered-by: ' + headers.get('x-powered-by'))

        if len(result['details']) > 0:
            result['status'] = 'failed'

        self.__results['http']['headers_banner_grabbing'] = result


    def __http_subresource_integrity(self):
        result = {}
        result['recommendation'] = 'Check the integrity of third-party hosted libraries in case they get compromised.'
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'
        result['status'] = 'passed'
        result['details'] = []

        body = self.__https['body'] if self.__https_present else self.__http['body']
        
        # Iterate through all script and link elements
        for resource in re.findall(r'(<(script|link).*?>)', body, re.I):
            resource = [x.strip().lower() for x in resource]
            # Ignore link elements that is not stylesheets
            if resource[1] == 'link' and resource[0].find('stylesheet') == -1:
                continue
            # Continue only if the itengrity attribute is missing
            if resource[0].find('integrity=') == -1:
                # Extract the URL
                url = re.findall(r'(src|href)="(.*?\/\/.*?)"', resource[0])
                if url:
                    result['details'].append(resource[0])
                    result['status'] = 'failed'
        self.__results['http']['subresource_integrity'] = result


    def __http_headers_cookies(self):
        result = {}
        result['recommendation'] = "Include the recommended flags to improve the security of cookies."
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'
        result['status'] = 'passed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('set-cookie'):
            result['details'] = ['No cookies found']
            self.__results['http']['headers_cookie_flags'] = result
            return

        for cookie in headers['set-cookie'].split('\n'):
            pos = cookie.find('=')
            cookie_name = cookie[0:pos]
            cookie = cookie.lower()
            
            result['status'] = 'passed'
            if 'secure' not in cookie:
                result['details'].append(cookie_name + ': Missing secure')
            if 'httponly' not in cookie:
                result['details'].append(cookie_name + ': Missing httponly')
            if 'samesite=lax' not in cookie or 'samesite=strict' not in cookie:
                result['details'].append(cookie_name + ': Missing samesite')
            
            if len(result['details']) > 0:
                result['status'] = 'failed'

            self.__results['http']['headers_cookie_flags'] = result


    def __http_headers_hsts(self):
        result = {}
        result['name'] = 'Strict-Transport-Security'
        result['recommendation'] = "Implement HSTS to force browsers to use HTTPS."
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        result['status'] = 'failed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('strict-transport-security'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_hsts'] = result
            return

        result['implemented'] = headers.get('strict-transport-security')

        flags = result['implemented'].split(';')
        flags = [x.strip().lower() for x in flags]

        result['status'] = 'passed'
        if 'preload' not in flags:
            result['details'].append('Missing preload')
        if 'includesubdomains' not in flags:
            result['details'].append('Missing includeSubDomains')
        if 'max-age=31536000' not in flags:
            result['details'].append('Missing max-age or max-age set too low')

        if len(result['details']) > 0:
            result['status'] = 'misconfigured'

        self.__results['http']['headers_hsts'] = result


    def __http_headers_cache_control(self):
        result = {}
        result['name'] = 'Cache-Control'
        result['recommendation'] = "Set Cache-Control to 'no-store' to completely prevent browser caching."
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'
        result['status'] = 'passed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('cache-control'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_cache_control'] = result
            return

        result['implemented'] = headers.get('cache-control')

        value = result['implemented'].lower()
        if value != 'no-store':
            result['status'] = 'failed'

        self.__results['http']['headers_content_security_policy'] = result


    # TODO: Need to improve the checks
    def __http_headers_content_security_policy(self):
        result = {}
        result['recommendation'] = 'Implement CSP properly to improve the security significantly.'
        result['name'] = 'Content-Security-Policy'
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        result['status'] = 'passed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('content-security-policy'):
            result['status'] = 2
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_content_security_policy'] = result
            return

        result['implemented'] = headers.get('content-security-policy')

        value = result['implemented'].lower()
        if value.find('unsafe-eval') > 0:
            result['details'].append('unsafe-eval in use')
        if value.find('unsafe-inline') > 0:
            result['details'].append('unsafe-inline in use')

        if len(result['details']) > 0:
            result['status'] = 'misconfigured'

        self.__results['http']['headers_content_security_policy'] = result


    def __http_headers_content_type_options(self):
        result = {}
        result['name'] = 'X-Content-Type-Options'
        result['recommendation'] = "Set the header to 'nosniff' to prevent browsers at converting the content type based on the content, which can mitigate some sorts of attacks.";
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
        result['status'] = 'failed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('x-content-type-options'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_content_type_options'] = result
            return

        result['implemented'] = headers.get('x-content-type-options')

        if result['implemented'] == 'nosniff':
            result['status'] = 'passed'

        self.__results['http']['headers_content_type_options'] = result


    def __http_headers_referrer_policy(self):
        result = {}
        result['recommendation'] = "Set a strict referrer policy to mitigate unnecessary disclosure of information."
        result['name'] = 'Referrer-Policy'
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
        result['status'] = 'failed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('referrer-policy'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_referrer_policy'] = result
            return

        result['implemented'] = headers.get('referrer-policy')

        value = result['implemented'].lower()
        if value == 'no-referrer' or value == 'strict-origin' or value == 'strict-origin-when-cross-origin':
            result['status'] = 'passed'

        self.__results['http']['headers_referrer_policy'] = result


    def __http_headers_frame_options(self):
        result = {}
        result['recommendation'] = "Use this header to mitigate clickjacking attacks."
        result['name'] = 'X-Frame-Options'
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        result['status'] = 'failed'
        result['details'] = []

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('x-frame-options'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_frame_options'] = result
            return

        result['implemented'] = headers.get('x-frame-options')

        value = result['implemented'].lower()
        if value == 'deny' or value == 'sameorigin' or value.find('allow-from') != -1:
            result['status'] = 'passed'
        self.__results['http']['headers_frame_options'] = result


    def __http_headers_xss_protection(self):
        result = {}
        result['name'] = 'X-XSS-Protection'
        result['recommendation'] = "Set the value to '1; mode=block' to prevent reflective XSS and stopping the remainding execution of the site.";
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
        result['details'] = []
        result['status'] = 'failed'
        
        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('x-xss-protection'):
            result['details'] = ['Header not implemented']
            self.__results['http']['headers_xss_protection'] = result
            return

        result['implemented'] = headers.get('x-xss-protection')

        if re.search('1;\s?mode=block', result['implemented']):
            result['status'] = 'passed'

        self.__results['http']['headers_xss_protection'] = result


    # TODO: Need also to create a check for the current origin somehow
    def __http_same_origin_policy_ajax(self):
        result = {}
        result['recommendation'] = ''
        result['ref'] = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
        result['details'] = []
        result['status'] = 'passed'

        headers = self.__https['headers'] if self.__https_present else self.__http['headers']

        if not headers.get('access-control-allow-origin'):
            result['details'] = ['Header not implemented']
            self.__results['http']['same_origin_policy_ajax'] = result
            return

        if headers.get('access-control-allow-origin') == '*':
            result['status'] = 'failed'
        self.__results['http']['same_origin_policy_ajax'] = result


    def __http_same_origin_policy_flash(self):
        result = {}
        result['recommendation'] = ''
        result['ref'] = 'https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html'
        result['status'] = 'passed'
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/crossdomain.xml')
        except:
            self.__results['http']['same_origin_policy_flash'] = result
            return
        if re.search('<allow-access-from domain="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 'failed'
        self.__results['http']['same_origin_policy_flash'] = result


    def __http_same_origin_policy_silverlight(self):
        result = {}
        result['recommendation'] = ''
        result['ref'] = 'https://docs.microsoft.com/en-us/previous-versions/windows/silverlight/dotnet-windows-silverlight/cc197955(v=vs.95)?redirectedfrom=MSDN'
        result['status'] = 'passed'
        url = None
        try:
            url = urllib.request.urlopen('http://' + self.__domain + '/clientaccesspolicy.xml')
        except:
            self.__results['http']['same_origin_policy_silverlight'] = result
            return
        if re.search('<domain uri="(https?://)?\*"', url.read().decode(), re.M):
             result['status'] = 'failed'
        self.__results['http']['same_origin_policy_silverlight'] = result


    def __email_spf(self):
        result = {}
        result['status'] = 'failed'
        result['recommendation'] = 'End the SPF TXT record with "-all" or "~all" to prevent email spoofing.'
        result['ref'] = 'https://en.wikipedia.org/wiki/Sender_Policy_Framework'
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "TXT")
        except:
            self.__results['email']['spf'] = result
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('[~|-]all', buf, re.M):
            result['status'] = 'passed'

        result['implemented'] = buf
        self.__results['email']['spf'] = result


    def __email_dmarc(self):
        result = {}
        result['recommendation'] = 'Set p=reject to enable the SPF policy and prevent email spoofing.'
        result['ref'] = 'https://en.wikipedia.org/wiki/DMARC'
        result['status'] = 'failed'

        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query('_dmarc.' + self.__domain, "TXT")
        except:
            self.__results['email']['dmarc'] = result
            return

        buf = ''
        for rdata in response:
            buf = buf + str(rdata)
        if re.search('p=none', buf, re.M):
            result['status'] = 'failed'
        else:
            result['status'] = 'passed'
        
        result['implemented'] = buf
        self.__results['email']['dmarc'] = result


    def __domain_caa(self):
        result = {}
        result['recommendation'] = 'Implement CAA to specify which CAs can issue certificates to your domain.'
        result['ref'] = 'https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization'
        result['status'] = 'failed'

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
            result['status'] = 'passed'
        self.__results['domain']['caa'] = result


    def __domain_dnssec(self):
        result = {}
        result['recommendation'] = 'Implement DNSSEC to help against DNS attacks.'
        result['ref'] = 'https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions'
        result['status'] = 'failed'

        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.__domain, "DNSKEY")
        except:
            self.__results['domain']['dnssec'] = result
            return

        result['status'] = 'passed'
        self.__results['domain']['dnssec'] = result


    def __domain_zone_transfer(self):
        result = {}
        result['recommendation'] = 'Restrict zone transfers to prevent disclosing of DNS data.'
        result['ref'] = 'https://en.wikipedia.org/wiki/DNS_zone_transfer'
        result['status'] = 'passed'

        answer = str(dns.resolver.query(self.__domain, 'NS').rrset)
        ns = answer.split("\n")[0].split(' ')[4]

        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, self.__domain))
        except:
            self.__results['domain']['zone_transfer'] = result
            return

        result['status'] = 'failed'
        self.__results['domain']['zone_transfer'] = result

        """
        # Results
        names = z.nodes.keys()
        for n in names:
            print(z[n].to_text(n))"""


    def __crypto_tls_versions(self):
        result = {}
        result['recommendation'] = ''
        result['ref'] = ''
        result['status'] = 'failed'

        depricated = ['tls1', 'tls1_1']
        for version in depricated:
            quit = subprocess.Popen(['echo', 'Q'], stdout=subprocess.PIPE)
            cmd = ['openssl', 's_client', '-' + version, '-connect', self.__domain, '-port', '443']
            try:
                output = subprocess.check_output(cmd, stdin=quit.stdout, stderr=subprocess.DEVNULL)
            except Exception as e:
                output = e.output
            if re.search('New, \(NONE\), Cipher is \(NONE\)', output.decode(), re.M):
                 result['status'] = 'passed'

            self.__results['crypto']['tls_support_' + version] = result


    def __crypto_ocsp_stapling(self):
        result = {}
        result['recommendation'] = 'Implement OCSP stapling to check the revocation status of certificates.'
        result['ref'] = 'https://en.wikipedia.org/wiki/OCSP_stapling'
        result['status'] = 'failed'

        #echo QUIT | openssl s_client -connect example.no:443 -status 2> /dev/null | grep -A 17 'OCSP response:'
        quit = subprocess.Popen(['echo', 'Q'], stdout=subprocess.PIPE)
        output = subprocess.check_output(['openssl', 's_client', '-connect', self.__domain, '-port', '443', '-status'], stdin=quit.stdout, stderr=subprocess.DEVNULL)

        if re.search('OCSP Response Status: successful', output.decode(), re.I):
            result['status'] = 'passed'
        
        self.__results['crypto']['ocsp_stapling'] = result


    def __crypto_rsa_key_strength(self):
        result = {}
        result['recommendation'] = ''
        result['ref'] = 'https://www.jscape.com/blog/should-i-start-using-4096-bit-rsa-keys'
        result['status'] = 'passed'

        #openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text -noout | grep "Public-Key"
        connect = subprocess.Popen(['openssl', 's_client', '-connect', self.__domain, '-port', '443'], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        cert = subprocess.check_output(['openssl', 'x509', '-text', '-noout'], stdin=connect.stdout, stderr=subprocess.DEVNULL)
        bit = re.findall('RSA Public-Key: \((\d+) bit\)', cert.decode())

        result['implemented'] = bit[0]

        if int(bit[0]) < 2048:
            result['status'] = 'failed'
        elif int(bit[0]) == 2048:
            result['status'] = 'passed'
        else:
            result['status'] = 'passed'

        self.__results['crypto']['rsa_key_strength'] = result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('./hcheck.py <domain>')
        sys.exit()
    check = hCheck(sys.argv[1])
    check.check_crypto()
    check.check_http()
    check.check_domain()
    check.check_email()
    check.get_stats()
    check.print_results()
