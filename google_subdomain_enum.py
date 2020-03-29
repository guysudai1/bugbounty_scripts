#!/usr/bin/env python

import requests, argparse, re
from threading import Thread
from urllib.parse import unquote

BASE_URL = "https://www.google.com/search?q="
#match_ip = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
match_url= r"[a-zA-Z0-9]{1}[a-zA-Z0-9.-]+"
found    = []


def main():
    global regex, BASE_URL

    parser = argparse.ArgumentParser(description="\
            This python program uses multiple searchengines and applications in order to find subdomains of a given domain.\
            ")
    parser.add_argument("-u", "--url", required=True, help="Url to check subdomains of (should be in the form of {site}.com).", metavar="url")
    parser.add_argument("-t", "--threads", required=False, default=1, type=int, help="Amount of threads to use.", metavar="threads")
    parser.add_argument("-l", "--log-file", required=False, type=str, help="Name of logfile to write to (Warning: this will overwrite the given file).", metavar="logfile")
    parser.add_argument("-H", "--header", required=False, action="append", help="Add headers to the request.")

    args = parser.parse_args()
    
    google_subdomains(args)

    if args.log_file is not None:
        write_to_logfile(args.log_file, found)

def get_header_dict(headers):
    hds = {}
    for header in headers:
        hds[header[:header.find(":")]] = header[header.find(":") + 2:]
    print("Headers: {}".format(str(hds)))
    return hds

def google_subdomains(args):
    global found, BASE_URL, regex
    print("[-] Starting google subdomain enumeration on {}...".format(args.url))
    base_filter = "site:*.{}".format(args.url)
    headers = get_header_dict(args.header)

    while True:
        req = unquote(requests.get(BASE_URL+ base_filter  + " -site:".join([""]+found), headers=headers).text)
        # Remove duplicates
        found_urls = set(re.findall(match_url + args.url , req))#"(" + match_ip + ")|(" + match_url + args.url + ")", req))
        print(BASE_URL + base_filter  + " -site:".join([""]+found) + "END", found_urls)
        print("en.help" in req, req)
        found_new_results = False
        for url in found_urls:
            if not url in found:
                found.append(url)
                print("[Google] Found new subdomain: {}".format(url))
                found_new_results = True

        if not found_new_results:
            break
    #print(BASE_URL + base_filter + " -site:".join([""] + found))
    print("[Google] FINISHED ENUMERATING ALL SUBDOMAINS [Google]")

def write_to_logfile(logfile, urls):
    print("Writing found subdomains to logfile {}...".format(logfile))
    with open(logfile, "w") as f:
        for url in urls:
            f.write("{}\n".format(url))

if __name__ == "__main__":
    main()
