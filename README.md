
<!-- TOC -->

- [vtsdk](#vtsdk)
        - [API Key](#api-key)
        - [Installation](#installation)
        - [Configuration](#configuration)
    - [vt.py](#vtpy)
        - [Prerrequisites](#prerrequisites)
        - [Usage](#usage)
    - [vt.sh](#vtsh)
        - [Prerrequisites](#prerrequisites-1)
        - [Usage](#usage-1)
    - [httpie](#httpie)
        - [Prerrequisites](#prerrequisites-2)

<!-- /TOC -->

# vtsdk
Virus Total API SDK in Python and in bash

### API Key
- For the apikey you just have to [register](https://www.virustotal.com/en/#signup) in VirusTotal Community (top right hand side of VirusTotal). Once registered, sign in into your account and you will find your public API in the corresponding menu item under your user name.

### Installation

Clone the repo or just get the vt.py/vt.sh file

### Configuration
- Put your key inside a file called *apikey.txt* in the same directory.

## vt.py

### Prerrequisites

The following packages need to be installed in fedora:
```
python-tkinter
python-pygments
python-requests
```

### Usage
- There are two options:
1. Interactive: you just run the sdk with:
```
chmod +x vt.py
./vt.py
```

[![asciicast](https://asciinema.org/a/Yd8ej63FO4Yd05UofjBI1czep.png)](https://asciinema.org/a/Yd8ej63FO4Yd05UofjBI1czep)

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
./vt.py -c url_report -r www.virustotal.com
```

## vt.sh

### Prerrequisites

It requires [httpie](https://httpie.org/) , in Fedora just install with:

```
dnf install httpie
```

### Usage

In this case there is no interactive version, so it requires the command and the resource:

```
chmod +x vt.sh
./vt.sh $command $resource [$comment]
```

Where command is one of this: filereport filescan filerescan urlreport urlscan domainreport ipaddressreport putcomments
And for putcomments you have to add an extra argument

For instance:
```
./vt.sh ipaddressreport 8.8.8.8
```

## httpie

List of examples using [httpie](https://httpie.org/)

### Prerrequisites

Set an environment variable with your APIKEY, for instance:

```
VT_API_KEY=`cat apikey.txt`
```

*file_report*
```
http GET https://www.virustotal.com/vtapi/v2/file/report apikey==${VT_API_KEY} resource==8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93
```

*file_scan*
```
http -f POST https://www.virustotal.com/vtapi/v2/file/scan apikey=${VT_API_KEY} file=@LICENSE
```

*file_rescan*
```
http POST https://www.virustotal.com/vtapi/v2/file/rescan apikey==${VT_API_KEY} resource==8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903
```
*url_report*
```
http GET https://www.virustotal.com/vtapi/v2/url/report apikey==${VT_API_KEY} resource==www.virustotal.com
```
*url_scan*
```
http POST https://www.virustotal.com/vtapi/v2/url/scan apikey==${VT_API_KEY} url==www.virustotal.com
```
*domain_report*
```
http GET https://www.virustotal.com/vtapi/v2/domain/report apikey==${VT_API_KEY} domain==www.virustotal.com
```
*ip_address_report*
```
http GET https://www.virustotal.com/vtapi/v2/ip-address/report apikey==${VT_API_KEY} ip==8.8.8.8
```
*put_comments*
```
http POST https://www.virustotal.com/vtapi/v2/comments/put apikey==${VT_API_KEY} resource==8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903 comment=="Testing httpie"
```