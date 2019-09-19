import urllib.request
import urllib.parse
import socket
import ssl
import dns.resolver

# status: 0 = pass, 1 = not proper, 2 = fail

class hCheck(object):

    __domain = ''
    __results = {}
    __http_response_headers = {}

    def __init__(self, domain):
        self.__domain = domain
        self.__http_get_headers('http://' + domain)

    def print_results(self):
        print(self.__results)

    def __http_get_headers(self, url):
        f = urllib.request.urlopen(url)
        current_url = f.geturl()
        self.__http_response_headers = f.info()

    #def __http_parse_headers(self):


    def http_check_return_to_https(self):
        status = 2
        url = urllib.request.urlopen('http://' + self.__domain).geturl()
        #print(current_url[0:5])
        if url[0:5] == 'https':
             status = 0
        self.__results['http_check_return_to_https'] = {'status': status}
           


hostname = 'isz.no'
context = ssl.create_default_context()



check = hCheck('isz.no')
check.print_results()

myResolver = dns.resolver.Resolver() #create a new instance named 'myResolver'
myAnswers = myResolver.query("google.com", "A") #Lookup the 'A' record(s) for google.com
for rdata in myAnswers: #for each response
    print rdata #print the data
