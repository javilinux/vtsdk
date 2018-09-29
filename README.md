# vtsdk
Virus Total API SDK in Python

### API Key
- For the apikey you just have to [register](https://www.virustotal.com/en/#signup) in VirusTotal Community (top right hand side of VirusTotal). Once registered, sign in into your account and you will find your public API in the corresponding menu item under your user name.

### Configuration
- Put your key inside a file called *apikey.txt* in the same directory.

### Prerrequisites

The following packages need to be installed in fedora:
```
python2-tkinter
python3-tkinter
python2-pygments
python3-pygments
python-requests
```

### Usage
- There are two options:
1. Interactive: you just run the sdk with:
```
python vt.py
```

2. Using command line arguments:
```
usage: vt.py [-h] -r RESOURCE [-m COMMENT] -c
             {file_report,file_scan,file_rescan,url_report,ip_report,domain_report,put_comment}

optional arguments:
  -h, --help            show this help message and exit
  -r RESOURCE, --resource RESOURCE
                        md5/sha1/sha256 hash of the file
  -m COMMENT, --comment COMMENT
                        Comment
  -c {file_report,file_scan,file_rescan,url_report,ip_report,domain_report,put_comment}, --command {file_report,file_scan,file_rescan,url_report,ip_report,domain_report,put_comment}
                        command
```

For instance:
```
python vt.py -c url_report -r www.virustotal.com
```
