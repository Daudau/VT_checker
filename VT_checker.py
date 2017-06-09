#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import requests
import hashlib
from optparse import OptionParser

# Tool version
VERSION = '0.1'

def main(argv=None):
  parser = OptionParser()
  parser.add_option("-k", "--key", dest="api_key", default=None,
    help="Api Key for VirusTotal submission.")
  parser.add_option("-u", "--urls", dest="urls", default=None,
    help="File containing the URLs to submit.")
  parser.add_option("-f", "--folder", dest="folder", default=None,
    help="Folder containing the files to submit (by MD5).")
  parser.add_option("-m", "--md5", dest="hashes", default=None,
    help="File containing the hashes to submit.")
  (options, args) = parser.parse_args()

  if not options.api_key:
    print("\033[91m[ERROR]\033[0m No Api Key provided.")
    sys.exit(-1)
  elif not any([options.urls, options.folder, options.hashes]):
    print("\033[91m[ERROR]\033[0m Nothing to submit.")
    sys.exit(-1)

  if options.urls:
    if not os.path.isfile(options.urls):
      print("\033[91m[ERROR]\033[0m Given file of URLs does not exist.")
      sys.exit(-1)
    with open(options.urls) as u:
      for url in u:
        params = {'apikey': options.api_key, 
          'resource': url}
        r = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
          data=params)
        while r.status_code == 204:
          r = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
            data=params)
        if r.status_code == 403:
          print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
            " url: " + url)
        else:
          try: 
            json_response = r.json()
            print("\033[94m[URL]\033[0m " + url.replace('\n', '') + ":")
            print("\tLast scan date: " + json_response['scan_date'])
            if json_response['positives'] == 0:
              print("\tDetection ratio: \033[92m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
            else:
              print("\tDetection ratio: \033[91m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
          except:
            print("\033[93m[WARNING]\033[0m Got invalid response format for " +
              "url: " + url)
            
  if options.folder:
    if not os.path.isdir(options.folder):
      print("\033[91m[ERROR]\033[0m Given folder does not exist.")
      sys.exit(-1)
    for root, directories, filenames in os.walk(options.folder):
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
          except:
            print("\033[93m[WARNING]\033[0m Got invalid response format for " + 
              "file: " + os.path.join(root,filename))

  if options.hashes:
    if not os.path.isfile(options.hashes):
      print("\033[91m[ERROR]\033[0m Given file of hashes does not exist.")
      sys.exit(-1)
    with open(options.hashes) as hashes:
      for h in hashes:
        params = {'apikey': options.api_key, 
          'resource': h}
        r = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
          data=params)
        while r.status_code == 204:
          r = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
            data=params)
        if r.status_code == 403:
          print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
            " hash: " + h)
        else:
          try: 
            json_response = r.json()
            print("\033[94m[HASH]\033[0m " + h.replace('\n', '') + ":")
            print("\tLast scan date: " + json_response['scan_date'])
            if json_response['positives'] == 0:
              print("\tDetection ratio: \033[92m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
            else:
              print("\tDetection ratio: \033[91m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
          except:
            print("\033[93m[WARNING]\033[0m Got invalid response format for " +
              "hash: " + h)
            

if __name__ == '__main__':
  main()

