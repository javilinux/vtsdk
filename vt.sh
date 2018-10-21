#!/bin/sh
#set -x

usagemsg()
{
	echo "Usage: vt.sh \$command \$resource [\$comment]"
	echo "Where command is one of this: ${commands_list[*]}"
	echo "And for put_comment you have to add an extra argument"
}

checkcommand()
{
    validcommand=false
    for i in "${commands_list[@]}"
    do
        if [ "$i" == "$1" ] ; then
            validcommand=true
        fi
    done
}

filereport()
{
    http GET https://www.virustotal.com/vtapi/v2/file/report apikey==$apikey resource==$resource    
}

filescan()
{
    http -f POST https://www.virustotal.com/vtapi/v2/file/scan apikey=$apikey file=@$resource
}

filerescan()
{
    http POST https://www.virustotal.com/vtapi/v2/file/rescan apikey==$apikey resource==$resource
} 

urlreport()
{
    http GET https://www.virustotal.com/vtapi/v2/url/report apikey==$apikey resource==$resource
} 

urlscan()
{
    http POST https://www.virustotal.com/vtapi/v2/url/scan apikey==$apikey url==$resource
}

domainreport()
{
    http GET https://www.virustotal.com/vtapi/v2/domain/report apikey==$apikey domain==$resource
} 

ipaddressreport()
{
    http GET https://www.virustotal.com/vtapi/v2/ip-address/report apikey==$apikey ip==$resource
} 

putcomments()
{
    http POST https://www.virustotal.com/vtapi/v2/comments/put apikey==$apikey resource==$resource comment=="$comment"
}

commands_list=(filereport filescan filerescan urlreport urlscan domainreport ipaddressreport putcomments)

if [ ! -f apikey.txt ]; then
    echo "apikey.txt File not found!"
    exit
fi
apikey=`cat apikey.txt`

if ! rpm -qa --quiet httpie ; then
    echo "httpie is NOT installed"
    exit
fi

if [ $# -lt 2 ] ; then
    echo "Not enough arguments supplied"
    usagemsg
    exit
fi
command=$1
resource=$2
comment=$3

checkcommand $1
if [ "$validcommand"  = true ]; then
    $1
else
	echo "Command should be one of this: ${commands_list[*]}"
fi