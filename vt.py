#!/usr/bin/python
# -*- coding: utf-8 -*-
# TODO:
# - git
# - Add functions: Domains, ips, comments, files
# - Add http to url if needed
# - Check url
# - json parser
# - use database
# DONE:
# - import apikey from file


import os
import requests
import json
from pygments import highlight
from pygments.lexers.data import JsonLexer
from pygments.formatters.terminal import TerminalFormatter
with open('apikey.txt', 'r') as myfile:
  myapikey = myfile.read().replace('\n','')

def menu():
	"""
	Function to clear screen and show menu
	"""
	os.system('clear') 
        print ("Choose an option")
	print ("\t1 - url report")
	print ("\t9 - salir")
         
        # Requesting an option
        optionMenu = raw_input("Choose option >> ")

        if (optionMenu=="1"):
            print ("")
            resource = raw_input("Choose url:")
            urlReport(resource)
        elif (optionMenu=="9"):
            print ("Pressed 9...\nExiting\n")
            exit()
        else:
            print ("")
            raw_input("No correct option selected...\npress any key to continue.")
            menu()

def urlReport(resource):
    """
    Function to get an url report
    Since we use scan=1 will automatically submit the URL for analysis if no report is found for it in VirusTotal's database.
    """
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': myapikey, 'resource':resource , 'allinfo':True, 'scan':'1'}
    response = requests.request('POST', url , params=params )
    if response.status_code != 200 :
        print("Failed")
        print(response.headers)
        print(response.status_code)
        print(response)
    else:
        json_str = json.dumps(response.json(), indent=2)
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))
    raw_input("Press any key to continue")
    menu()

if __name__== "__main__":
  menu()