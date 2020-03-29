#!/usr/bin/env python3

import requests, argparse, re, os.path
from threading import Thread
from urllib.parse import unquote
from random import randint


"""
Author: Guy Sudai
Description: 
Custom tool by Guy Sudai (inspired by gobuster, dirb, dirbuster) in order to detect hidden content in websites and notifying the user.   

Detection Techniques used:
    - Status codes
    - Length

Usage:
python3 ./content_discovery.py -u www.google.com -w /path/to/rockyou.txt -w /path/to/different/wordlist.txt --method=status

"""

class Discoverer:
    def __init__(self, url, wordlists, method_of_detection, http_methods, extensions, headers, cookies, user_agents, outfile, code=""):
        """

        PARAMETERS

        @url : url to content discover, comprised of scheme + :// + domain + path
        default: None, required

        @wordlists : array comprised of wordlist paths
        default: None, required

        @method_of_detection => { 
            status_code : Discover content by status code
            length      : Discover content by length (useful when status code is always the same regardless if content exists)
            custom      : Allows content discovery by inserting python code (short)
        }
        default "status_code"

        @http_methods => {
            GET,
            POST,
            TRACE,
            OPTIONS,
            PUT,
            HEAD,
            PATCH
        }
        default [GET]

        @extensions : array comprised of extensions (for example [php, txt]) 
        default []

        @headers    : headers in the form of ["Header: Value"]
        default []

        @cookies    : cookie values, in the form of ["key=val"]
        default []

        @user_agents: user agents in order to add a form of stealthiness and fingerprint disguise. In the form of ["useragent"]
        default []
        """
        
        self.url        = url
        self.wordlists  = wordlists
        self.method     = method_of_detection
        self.methods    = set([method.upper() for method in http_methods])
        self.exts       = set([x.strip() for x in extensions.split(",")] + [""])
        self.headers    = headers
        self.agents     = user_agents
        self.cookies    = cookies
        self.outfile    = outfile
        self.found      = []
        self.regex      = re.compile(
                r'^(?:http)s?://' # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                r'localhost|' #localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                r'(?::\d+)?' # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        self.validate_parameters()
        

    def validate_parameters(self):
        # Validate URL
        if (re.match(self.regex, self.url) is None):
            # According to RFC3986 
            # URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
            print("[XXX] Invalid URL, please enter a URL in the following format:\nschema + :// + authority + path, for example: https://example.com\n")
            exit(1)
        
        if (self.url[-1] != "/"):
            self.url += "/"
        
        # Validate wordlists 
        for wordlist in self.wordlists:
            if not os.path.isfile(wordlist):
                print(f"File {wordlist} does not exist.")
                exit(1)

        # Check if detection method is valid
        valid_methods = ["status_code", "custom", "length"]
        if self.method not in valid_methods:
            print(f"[XXX] Invalid method, please use one of the following methods: {', '.join(valid_methods)}")
            exit(1)

        # Check if given http variables are valid
        valid_methods = ["GET", "HEAD", "POST", "PUT", "OPTIONS", "PATCH"]
        for method in self.methods:
            if method not in valid_methods:
                print(f"[XXX] Invalid HTTP method, please use one of the following: {', '.join(valid_methods)}")
    

    def enumerate(self):
        wordlist_generator = self.load_wordlists()\

        if self.method == "length":
            # Generate bad request to check length
            self.bad_request = self.send_request("bgjkdnbsvdsbkjalsjkcskamvdskmlavafsklnvds12345")

        self.successful_words = []
        for word in wordlist_generator:
            request = self.send_request(word)
            good = False
            # Detection methods here
            if self.method == "status_code":
                methods, good = self.detect_status(request)
            elif self.method == "length":
                methods, good = self.detect_status(request)
            elif self.method == "custom":
                # TODO: Add feature to support custom code to be evaluated in python
                pass
            
            if good:
                self.successful_words.append((word, methods))
                print(f"[+] Found {self.url + word}, works with: {', '.join([method for method, val in zip(methods.keys(), methods.values()) if val])}")


    def write_to_file(self):
        try:
            print(f"[*] Writing words to file {self.outfile}...")
            with open(self.outfile, "w") as f:
                f.write("\n".join(self.successful_words))
            print(f"[=] Wrote words to file {self.outfile}")
        except Exception as e:
            print(f"[X] Failed: {e}")

    def detect_length(self, request):
        # Check length of page that definitely doesn't exist
        # (Looking for fixed error page)
        methods = {}
        good = False

        for request1, bad_request, method in zip(request, self.bad_request, self.methods):
            methods[method] = request1.headers["Content-Length"] == request1.headers["Content-Length"]
            if methods[method]:
                good = True

        return methods, good

    def detect_status(self, request):
        methods = {}
        good = False
        for request, method in zip(request, self.methods):
            methods[method] = request.status_code != 404 and request.status_code != 501
            if methods[method]:
                good = True

        return methods, good

    def send_request(self, word):
        headers     = self.add_headers()
        useragent   = "My custom useragent V2"
        if self.agents is not None and self.agents != [] and type(self.agents) == type([]):
            useragent = self.agents[randint(len(self.agents))]
        headers["User-Agent"] = useragent
        cookies     = self.add_cookies()
        url        = self.url + word
        methods     = {
            "GET"     : requests.get,
            "POST"    : requests.post,
            "PUT"     : requests.put,
            "HEAD"    : requests.head,
            "OPTIONS" : requests.options,
            "PATCH"   : requests.patch
        }
        
        all_method_requests = []
        for method in self.methods:
            all_method_requests.append(methods[method](url, headers=headers, cookies=cookies))

        return all_method_requests
            

    def add_cookies(self):
        
        def parse_cookie(cookie):
            index_equal = cookie.find("=")
            return cookie[:index_equal].strip(), cookie[index_equal + 1:].strip()
        cookies = {}        
        if self.cookies is None:
            return cookies
        for cookie in self.cookies:
            head, value = parse_cookie(cookie)
            cookies[head] = value
        return cookies


    def add_headers(self):

        def parse_header(header):
            index_header = header.find(":")
            return header[:index_header], header[index_header + 1:].lstrip() 

        headers = {}
        if self.headers is None:
            return headers
        for header in self.headers:
            head, value = parse_header(header)
            headers[head] = value
        return headers


    def load_wordlists(self):
        def validate_word(word):
            query_start     = word.find("?")
            comment_start   = word.find("#")
            if (query_start == -1 and comment_start == -1):
                return word
            query_start, comment_start     = query_start if query_start != -1 else len(word), comment_start if comment_start != -1 else len(word) 
            return word[:min([query_start, comment_start])]

        for wordlist in self.wordlists:
            with open(wordlist, "r") as f:
                content = f.readlines()

            for line in content:
                # Check validity of line
                valid_line = validate_word(line)
                if valid_line == "":
                    continue
                for ext in self.exts:
                    if ext == "":
                        yield line.rstrip()
                    else:
                        yield line.rstrip() + "." + ext
        

def main():
    parser = argparse.ArgumentParser(description="\
            This python program uses multiple methods in order to discover new content to a website.\
            ")
    #required = parser.add_subparsers(title='Required variables', description='Variables for defining the target', help='additional help')
    #optional_parser = optional.add_parser("parser1")
    parser.add_argument("-u", "--url", required=True, help="Url to check subdomains of (should be in the form of https://example.com).", metavar="url") #
    parser.add_argument("-w", "--wordlist", required=True, action="append", help="Find content with wordlists.", metavar="wordlists") #
    parser.add_argument("-t", "--threads", required=False, default=1, type=int, help="Amount of threads to use.", metavar="threads")
    parser.add_argument("-o", "--output", required=False, type=str, help="Name of logfile to write to (Warning: this will overwrite the given file).", metavar="outfile") #
    parser.add_argument("-H", "--header", required=False, action="append", help="Add headers to the requests.", metavar="headers") #
    parser.add_argument("-C", "--cookie", required=False, action="append", help="Add cookies to the requests.", metavar="cookies") #
    parser.add_argument("-U", "--user-agent", required=False, action="append", help="Add a random user agent to the requests.", metavar="agents") #
    parser.add_argument("-M", "--methods", required=False, action="append", help="Select methods to use. (GET, POST, PUT, HEAD, OPTIONS, PATCH)", default=["GET"], metavar="methods") #
    parser.add_argument("-D", "--detection", required=False, type=str, help="Select method to use.(status_code, length, custom)", default="status_code", metavar="detection") #
    parser.add_argument("-x", "--extension", required=False, type=str, help="Add extensions to the content.", default="", metavar="extensions") #
    parser.add_argument("-c", "--code", required=False, type=str, help="Use code with custom discovery method.", metavar="code") #


    args = parser.parse_args()
    from pprint import pprint
    pprint(args)
    discover = Discoverer(args.url, args.wordlist, args.detection, args.methods, args.extension, args.header, args.cookie, args.user_agent, args.code)
    try:
        discover.enumerate()
    except KeyboardInterrupt:
        # Check if output file is inputted
        if discover.outfile is not None:
            discover.write_to_file()
        print("Exiting...")
        exit(1)        
    
    # Check if output file is inputted
    if discover.outfile is not None:
        discover.write_to_file()
    
if __name__ == "__main__":
    main()
