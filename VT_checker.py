#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import requests
import hashlib
import re
from optparse import OptionParser

# Tool version
VERSION = '0.1'


def submit_ip_or_domain(resource_type, uri, resource, api_key, output):
  f = open(output, "a")
  params = {'apikey': api_key, 
    'ip': resource}
  while True:
    r = requests.get('https://www.virustotal.com/vtapi/v2' + uri,
      params=params)
    if r.status_code is not 204:
      break
  if r.status_code == 403:
    print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
      " resource: " + re)
  else:
    try: 
      json_response = r.json()
      if json_response['response_code'] == 1:
        print("\033[94m[" + resource_type + "]\033[0m " +
          resource + ":")
        for url in json_response['detected_urls']:
          if url['positives'] == 0:
            print("\t" + url["url"] + ": \033[92m" + 
              str(url['positives']) + "/" + 
              str(url['total']) + "\033[0m\n")
          else:
            print("\t" + url["url"] + ": \033[91m" + 
              str(url['positives']) + "/" + 
              str(url['total']) + "\033[0m\n")
          f.write(resource_type + "," + resource + "," + 
            str(json_response['response_code']) + 
            "," + url['scan_date'] + "," +
            str(url['positives']) +
            ',' + str(url['total']) + "," + url['url'] + "\n") 
      else :
        print("\033[94m[" + resource_type + "]\033[0m " +
          resource + ":")
        print("\t" + json_response['verbose_msg'] + "\n")
        f.write(resource_type + "," + resource + "," +
          str(json_response['response_code']) + 
          "," + json_response['verbose_msg'] + "\n") 
    except:
      print("\033[93m[WARNING]\033[0m Got invalid response format for " +
        "resource: " + resource + "\n")
  f.close()


def submit_hash_or_url(resource_type, uri, resource, api_key, output):
  f = open(output, "a")
  params = {'apikey': api_key, 
    'resource': resource}
  while True:
    r = requests.post('https://www.virustotal.com/vtapi/v2' + uri,
      data=params)
    if r.status_code is not 204:
      break
  if r.status_code == 403:
    print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
      " resource: " + re)
  else:
    try: 
      json_response = r.json()
      if json_response['response_code'] == 1:
        print("\033[94m[" + resource_type + "]\033[0m " +
          resource + ":")
        print("\tLast scan date: " + json_response['scan_date'])
        if json_response['positives'] == 0:
          print("\tDetection ratio: \033[92m" + 
            str(json_response['positives']) + "/" + 
            str(json_response['total']) + "\033[0m\n")
        else:
          print("\tDetection ratio: \033[91m" + 
            str(json_response['positives']) + "/" + 
            str(json_response['total']) + "\033[0m\n")
        f.write(resource_type + "," + resource + "," +
          str(json_response['response_code']) + 
          "," + json_response['scan_date'] + "," +
          str(json_response['positives']) +
          ',' + str(json_response['total']) + "\n") 
      else :
        print("\033[94m[" + resource_type + "]\033[0m " +
          resource + ":")
        print("\t" + json_response['verbose_msg'] + "\n")
        f.write(resource_type + "," + resource + "," + 
          str(json_response['response_code']) + 
          "," + json_response['verbose_msg'] + "\n") 
    except:
      print("\033[93m[WARNING]\033[0m Got invalid response format for " +
        "resource: " + resource + "\n")
  f.close()


def main(argv=None):
  parser = OptionParser()
  parser.add_option("-k", "--key", dest="api_key", default=None,
    help="Api Key for VirusTotal submission.")
  parser.add_option("-d", "--directory", dest="directory", default=None,
    help="Directory of files to submit.")
  parser.add_option("-f", "--file", dest="file", default=None,
    help="File containing a list of resources (hash, url, IP, etc.).")
  parser.add_option("-o", "--output", dest="output", default="output.csv",
    help="Filename for the CSV output.")
  (options, args) = parser.parse_args()

  if not options.api_key:
    print("\033[91m[ERROR]\033[0m No Api Key provided.")
    sys.exit(-1)
  elif not any([options.file, options.directory]):
    print("\033[91m[ERROR]\033[0m Nothing to submit.")
    sys.exit(-1)

  if options.file:
    if not os.path.isfile(options.file):
      print("\033[91m[ERROR]\033[0m Given file does not exist: " + options.file)
      sys.exit(-1)
    with open(options.file) as resource_file:
      for res in resource_file:
        resource = res.replace('\n', '')
        # If resource is a MD5 hash
        if re.match(r"([a-fA-F\d]{32}$)", resource):
          submit_hash_or_url("HASH(MD5)", "/file/report", resource, 
            options.api_key, options.output)
        # If resource is a SHA1 hash
        elif re.match(r"([a-fA-F\d]{40}$)", resource):
          submit_hash_or_url("HASH(SHA1)", "/file/report", resource, 
            options.api_key, options.output)
        # If resource is a SHA256 hash
        elif re.match(r"([a-fA-F\d]{64}$)", resource):
          submit_hash_or_url("HASH(SHA256)", "/file/report", resource, 
            options.api_key, options.output)
        # If resource is an IP address
        elif re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", resource):
          submit_ip_or_domain("IP", "/ip-address/report", resource, 
            options.api_key, options.output)
        # If resource is a domain name
        elif re.match(r"(^[a-z0-9]([a-z0-9-]+\.){1,}[a-z0-9]+\Z)", resource):
          submit_ip_or_domain("DOMAIN", "/domain/report", resource, 
            options.api_key, options.output)
        # If resource is a URL
        elif re.match(r"(^(http[s]?://)?[a-z0-9]([a-z0-9-]+\.){1,}[a-z0-9]+)",
          resource):
          submit_hash_or_url("URL", "/url/report", resource, 
            options.api_key, options.output)
        else:
          print("\033[93m[WARNING]\033[0m Resource " + resource + 
            " does not match any pattern.\n")
                
  if options.directory:
    if not os.path.isdir(options.directory):
      print("\033[91m[ERROR]\033[0m Given folder does not exist.")
      sys.exit(-1)
    f = open(options.output, "a")
    for root, directories, filenames in os.walk(options.directory):
      for filename in filenames: 
        md5 =  hashlib.md5(open(os.path.join(root,filename), 
          'rb').read()).hexdigest()
        params = {'apikey': options.api_key, 
          'resource': md5}
        r = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
          data=params)
        while r.status_code == 204:
          r = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
            data=params)
        if r.status_code == 403:
          print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
            " file: " + os.path.join(root,filename) + " (" + md5 + ")")
        else:
          try: 
            json_response = r.json()
            if json_response['response_code'] == 1:
              print("\033[94m[FILE]\033[0m " + os.path.join(root,filename) + 
                "(" + md5 + "):")
              print("\tLast scan date: " + json_response['scan_date'])
              if json_response['positives'] == 0:
                print("\tDetection ratio: \033[92m" + 
                  str(json_response['positives']) + "/" + 
                  str(json_response['total']) + "\033[0m\n")
              else:
                print("\tDetection ratio: \033[91m" + 
                  str(json_response['positives']) + "/" + 
                  str(json_response['total']) + "\033[0m\n")
              f.write("FILE," + resource + "," + 
                str(json_response['response_code']) + 
                "," + json_response['scan_date'] + "," +
                str(json_response['positives']) +
                ',' + str(json_response['total']) + "\n") 
            else :
              print("\033[94m[FILE]\033[0m " + os.path.join(root,filename) + 
                "(" + md5 + "):")
              print("\t" + json_response['verbose_msg'] + "\n")
              f.write("FILE," + resource + "," +
                str(json_response['response_code']) + 
                "," + json_response['verbose_msg'] + "\n") 
          except:
            print("\033[93m[WARNING]\033[0m Got invalid response format for " +
              "resource: " + os.path.join(root,filename))
    f.close()

if __name__ == '__main__':
  main()

