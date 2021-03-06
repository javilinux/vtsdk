#! /usr/bin/env python
# -*- coding: utf-8 -*-
# 

import os
import requests
import json
import socket
import Tkinter,tkFileDialog
import argparse
import sys
import hashlib
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
    print ("\t2 - domain report")
    print ("\t3 - ip address report")
    print ("\t4 - Get comments")
    print ("\t5 - Put comment")
    print ("\t6 - File report")
    print ("\t7 - File rescan")
    print ("\t8 - File scan")
    print ("\t9 - salir")
        
    # Requesting an option
    optionMenu = raw_input("Choose option >> ")

    if (optionMenu=="1"):
        print ("")
        resource = raw_input("Choose url:")
        urlReport(resource)
    elif (optionMenu=="2"):
        print ("")
        resource = raw_input("Choose domain:")
        domainReport(resource)
    elif (optionMenu=="3"):
        print ("")
        resource = raw_input("Choose IP:")
        ipChecker(resource)
        ipReport(resource)
    elif (optionMenu=="4"):
        print ("")
        resource = raw_input("Enter md5/sha1/sha256 hash of the file or the URL itself you want to retrieve comments from: ")
        getComments(resource)
    elif (optionMenu=="5"):
        print ("")
        resource = raw_input("Enter md5/sha1/sha256 hash of the file or the URL itself you want to put a comment on: ")
        comment = raw_input("Enter comment to add: ")
        putComment(resource,comment)
    elif (optionMenu=="6"):
        print ("")
        resource = raw_input("Enter md5/sha1/sha256 hash of the file you want to get the report: ")
        fileReport(resource)
    elif (optionMenu=="7"):
        print ("")
        resource = raw_input("Enter md5/sha1/sha256 hash of the file you want to get rescanned: ")
        fileRescan(resource)
    elif (optionMenu=="8"):
        root = Tkinter.Tk()
        root.withdraw()
        filename = tkFileDialog.askopenfilename(parent=root,title='Choose a file')
        fileScan(filename)
    elif (optionMenu=="9"):
        print ("Pressed 9...\nExiting\n")
        exit()
    else:
        print ("")
        raw_input("No correct option selected...\npress any key to continue.")
        menu()

def responseParser(response):
    if response.status_code != 200 :
        print("Failed")
        print(response.headers)
        print(response.status_code)
        print(response)
    else:
        json_str = json.dumps(response.json(), indent=2)
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))

def urlReport(resource):
    """
    Function to get an url report
    Since we use scan=1 will automatically submit the URL for analysis if no report is found for it in VirusTotal's database.
    """
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': myapikey, 'resource':resource , 'allinfo':True, 'scan':'1'}
    response = requests.request('POST', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def domainReport(resource):
    """
    Function to get an url report
    """
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': myapikey, 'domain':resource }
    response = requests.request('GET', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def ipReport(resource):
    """
    Function to get an ip address report
    """
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': myapikey, 'ip':resource }
    response = requests.request('GET', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def ipChecker(resource):
    """
    Function to validate ipv4 -addresses
    """
    try:
        socket.inet_aton(resource)
    except socket.error:
        print "not ipv4 address"
        raw_input("Press any key to continue")
        menu()

def getComments(resource):
    """
    Function to get comments from a resource
    """
    url = 'https://www.virustotal.com/vtapi/v2/comments/get'
    params = {'apikey': myapikey, 'resource':resource }
    response = requests.request('GET', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def putComment(resource,comment):
    """
    Function to put a comments to a resource
    """
    url = 'https://www.virustotal.com/vtapi/v2/comments/put'
    params = {'apikey': myapikey, 'resource':resource, 'comment':comment }
    response = requests.request('POST', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def fileReport(resource):
    """
    Function to get report of a file
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': myapikey, 'resource':resource}
    response = requests.request('GET', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def fileRescan(resource):
    """
    Function to get a file Rescanned
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/rescan'
    params = {'apikey': myapikey, 'resource':resource}
    response = requests.request('POST', url , params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

def fileScan(resource):
    """
    Function to get a Scan a file.
    First check if the file exists already on Virustotal, if so it ask for rescan or get the report, if not it is scanned.
    """
    f = open(resource,"rb")
    bytes = f.read() # read entire file as bytes
    sha256_hash = hashlib.sha256(bytes).hexdigest()
    params = {'apikey': myapikey, 'resource':sha256_hash}
    response = requests.request('GET', 'https://www.virustotal.com/vtapi/v2/file/report' , params=params )
    if ((response.json()["response_code"]) == 1 ):
        print("File already present on virustotal")
        option = raw_input("Press 1 to rescan, 2 to get the report\t")
        if option == "1":
            fileRescan(sha256_hash)
        elif option == "2":
            fileReport(sha256_hash)
        else:
            menu()
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': myapikey}
    files = {'file': (resource, f)}
    response = requests.request('POST', url , files=files, params=params )
    responseParser(response)
    raw_input("Press any key to continue")
    menu()

if __name__== "__main__":
    if (len(sys.argv) > 1):
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--resource", required=True, help="md5/sha1/sha256 hash of the file")
        parser.add_argument("-m", "--comment", required=False, help="Comment")
        parser.add_argument("-c", "--command", required=True, 
            choices=['file_report','file_scan','file_rescan','url_report','ip_report','domain_report','put_comment'], help="command")
        args = parser.parse_args()
        if args.command == 'file_report' :
            fileReport(args.resource)
        elif args.command == 'file_scan' :
            fileScan(args.resource)
        elif args.command == 'file_rescan' :
            fileRescan(args.resource)
        elif args.command == 'url_report' :
            urlReport(args.resource)
        elif args.command == 'ip_report' :
            ipReport(args.resource)
        elif args.command == 'domain_report' :
            domainReport(args.resource)
        elif args.command == 'put_comment' :
            if (not hasattr(args,'comment')):
                print("-m , --comment <comment> argument required")
                exit()
            putComment(args.resource,args.comment)
        exit()
    menu()
