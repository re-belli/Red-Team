#!/bin/bash

if [ "$EUID" -ne 0 ]
then 
    echo "Please run as root"
    exit
fi


# installation steps for Debian

apt update

# install necassary apt packages 

apt install ldap-utils nmap smbclient smbmap python3-pip git python3-venv

# create python virual environment

python3 -m venv /root/machine_recon_scanning

# Enter virtual environment 

source /root/machine_recon_scanning/bin/activate

# install impacket

pip install impacket

# install crackmapexec

pip install crackmapexec

# install kerbrute

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute

chmod 775 kerbrute

ln -s $(pwd)/kerbrute /usr/local/bin/

chmod 775 /usr/local/bin/kerbrute

#install seclists 

git clone https://github.com/danielmiessler/SecLists.git

mkdir -p /usr/share/seclists

cp -r SecLists/* /usr/share/seclists


#install enum4linux-ng

git clone https://github.com/cddmp/enum4linux-ng.git

ln -s $(pwd)/enum4linux-ng/enum4linux-ng.py /usr/local/bin/

chmod 775 /usr/local/bin/enum4linux-ng.py

#install ffuf

wget https://github.com/ffuf/ffuf/releases/download/v1.5.0/ffuf_1.5.0_linux_amd64.tar.gz

tar -xvf ffuf_1.5.0_linux_amd64.tar.gz

ln -s $(pwd)/ffuf /usr/local/bin/

chmod 775 /usr/local/bin/ffuf

# install MachineRecon

wget https://raw.githubusercontent.com/re-belli/pentesting_notes/refs/heads/main/automated_recon_htb/machinerecon.sh

ln -s $(pwd)/machinerecon.sh /usr/local/bin/

chmod 775 /usr/local/bin/machinerecon.sh

deactivate
