#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import requests
import hashlib
from optparse import OptionParser

# Tool version
VERSION = '0.1'


def submit_resource(resource_type, uri, resource_file, api_key, output):
  if not os.path.isfile(resource_file):
    print("\033[91m[ERROR]\033[0m Given file does not exist: " + resource_file)
    sys.exit(-1)
  f = open(output, "w")
  with open(resource_file) as resource:
    for re in resource:
      params = {'apikey': api_key, 
        'resource': re}
      r = requests.post('https://www.virustotal.com/vtapi/v2' + uri,
        data=params)
      while r.status_code == 204:
        r = requests.post('https://www.virustotal.com/vtapi/v2' + uri,
          data=params)
      if r.status_code == 403:
        print("\033[93m[WARNING]\033[0m Got 403 status code when submitting" +
          " resource: " + re)
      else:
        try: 
          json_response = r.json()
          if json_response['response_code'] == 1:
            print("\033[94m[" + resource_type + "]\033[0m " +
              re.replace('\n', '') + ":")
            print("\tLast scan date: " + json_response['scan_date'])
            if json_response['positives'] == 0:
              print("\tDetection ratio: \033[92m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
            else:
              print("\tDetection ratio: \033[91m" + 
                str(json_response['positives']) + "/" + 
                str(json_response['total']) + "\033[0m\n")
            f.write(resource_type + "," + str(json_response['response_code']) + 
              "," + json_response['scan_date'] + "," +
              str(json_response['positives']) +
              ',' + str(json_response['total']) + "\n") 
          else :
            print("\033[94m[" + resource_type + "]\033[0m " +
              re.replace('\n', '') + ":")
            print("\t" + json_response['verbose_msg'] + "\n")
            f.write(resource_type + "," + str(json_response['response_code']) + 
              "," + json_response['verbose_msg'] + "\n") 
        except:
          print("\033[93m[WARNING]\033[0m Got invalid response format for " +
            "resource: " + re)
  f.close()


def main(argv=None):
  parser = OptionParser()
  parser.add_option("-k", "--key", dest="api_key", default=None,
    help="Api Key for VirusTotal submission.")
  parser.add_option("-u", "--urls", dest="urls", default=None,
    help="File containing the URLs to submit.")
  parser.add_option("-d", "--domains", dest="domains", default=None,
    help="File containing the domains to submit.")
  parser.add_option("-i", "--ips", dest="ips", default=None,
    help="File containing the IPs to submit.")
  parser.add_option("-m", "--hashes", dest="hashes", default=None,
    help="File containing the hashes to submit.")
  parser.add_option("-f", "--folder", dest="folder", default=None,
    help="Folder containing the files to submit (by MD5).")
  parser.add_option("-o", "--output", dest="output", default="output.csv",
    help="Filename for the CSV output.")
  (options, args) = parser.parse_args()

  if not options.api_key:
    print("\033[91m[ERROR]\033[0m No Api Key provided.")
    sys.exit(-1)
  elif not any([options.urls, options.folder, options.hashes]):
    print("\033[91m[ERROR]\033[0m Nothing to submit.")
    sys.exit(-1)

  if options.urls:
    submit_resource("URL", "/url/report", options.urls, options.api_key,
      options.output)
                
  if options.domains:
    submit_resource("DOMAIN", "/domain/report", options.domains, 
      options.api_key, options.output)

  if options.ips:
    submit_resource("IP", "/ip-address/report", options.ips, options.api_key,
      options.output)

  if options.hashes:
    submit_resource("HASH", "/file/report", options.hashes, options.api_key,
      options.output)

  if options.folder:
    if not os.path.isdir(options.folder):
      print("\033[91m[ERROR]\033[0m Given folder does not exist.")
      sys.exit(-1)
    f = open(options.output, "w")
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
              f.write("FILE," + str(json_response['response_code']) + 
                "," + json_response['scan_date'] + "," +
                str(json_response['positives']) +
                ',' + str(json_response['total']) + "\n") 
            else :
              print("\033[94m[FILE]\033[0m " + os.path.join(root,filename) + 
                "(" + md5 + "):")
              print("\t" + json_response['verbose_msg'] + "\n")
              f.write("FILE," + str(json_response['response_code']) + 
                "," + json_response['verbose_msg'] + "\n") 
          except:
            print("\033[93m[WARNING]\033[0m Got invalid response format for " +
              "resource: " + os.path.join(root,filename))
    f.close()

if __name__ == '__main__':
  main()

