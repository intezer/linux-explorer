#!/bin/bash

is_first_run=false

# ========================= Setup external tools =========================
if [ ! -f yara/yara ] || [ ! -f chkrootkit/chkrootkit ] ; then

    is_first_run=true

    if [ -f /etc/redhat-release ]; then

      sudo yum -y install wget

    fi

    if [ -f /etc/lsb-release ]; then

      sudo apt-get install wget

    fi

fi

if [ ! -f yara/yara ]; then

    if [ -f /etc/redhat-release ]; then
      echo "Installing dependencies for yara/CentOS..."

      # YARA
      sudo yum -y install automake libtool make gcc

    fi

    if [ -f /etc/lsb-release ]; then
      echo "Installing dependencies for yara/Ubuntu..."

      # YARA
      sudo apt-get install -y automake libtool make gcc

    fi

    # Build YARA from source
    rm master.tar.gz
    wget https://github.com/VirusTotal/yara/archive/master.tar.gz -O master.tar.gz
    tar -zxf master.tar.gz
    mv yara-master yara
    cd yara
    ./bootstrap.sh
    ./configure
    make # build without install. we'll use the binaries directly.
    cd ..

fi

if [ ! -f chkrootkit/chkrootkit ] ; then

    if [ -f /etc/redhat-release ]; then
      echo "Installing dependencies for chkrootkit/CentOS..."

      # NETSTAT
      sudo yum -y install net-tools

    fi

    if [ -f /etc/lsb-release ]; then
      echo "Installing dependencies for chkrootkit/Ubuntu..."

      # NETSTAT
      sudo apt-get install -y net-tools

    fi

    # Build chkrootkit from source
    rm master.tar.gz
    wget https://github.com/omri9741/chkrootkit/archive/master.tar.gz -O master.tar.gz
    tar -zxf master.tar.gz
    mv chkrootkit-master chkrootkit
    rm master.tar.gz
    cd chkrootkit
    make sense
    cd ..

fi

# ========================= Install Python pip if needed =========================
if [ ! -x "$(command -v pip3)" ] && [ ! -x "$(command -v pip3.6)" ]; then
    echo "python3/pip not installed! installing pip..."

    is_first_run=true

    if [ -f /etc/redhat-release ]; then

      sudo yum -y install https://centos7.iuscommunity.org/ius-release.rpm
      sudo yum -y install gcc python36-devel python36u-pip
      sudo ln -s /usr/bin/python3.6 /usr/bin/python3

    fi

    if [ -f /etc/lsb-release ]; then

      sudo apt-get install -y python3 python3-pip

    fi

fi

# ========================= 1st run =========================
if [ "$is_first_run" = true ] ; then

# ========================= Install requirements =========================
    # First try to install while ignoring conflicts in order to avoid any errors
    sudo python3 -m pip install --ignore-installed -r requirements.txt
    sudo python3 -m pip install -r requirements.txt

# ========================= Update YARA signatures =========================
    echo -e "\033[33m[*] fetching up-to-date yara signatures...\033[0m"
    ./update_signatures.sh

fi

# ========================= Start Linux Expl0rer =========================
echo -e "\033[33m[*] starting Linux Expl0rer...\033[0m"
sudo python3 linux_explorer.py
