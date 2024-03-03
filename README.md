# This project is no longer maintained!

# Linux Expl0rer
Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask.

![Alt Text](https://github.com/intezer/linux-explorer/raw/master/image.gif)

## Capabilities
### ps
* View full process list
* Inspect process memory map & fetch memory strings easly
* Dump process memory in one click
* Automatically search hash in public services
  * [VirusTotal](https://www.virustotal.com/#/home/upload)
  * [Intezer Analyze](https://analyze.intezer.com)
  * [AlienVault OTX](https://otx.alienvault.com/)
  * [MalShare](https://malshare.com/)
### users
* users list
### find
* Search for suspicious files by name/regex
### netstat
* Whois
### logs
* syslog
* auth.log(user authentication log)
* ufw.log(firewall log)
* bash history
### anti-rootkit
* chkrootkit
### yara
* Scan a file or directory using YARA signatures by @Neo23x0
* Scan a running process memory address space
* Upload your own YARA signature
  
## Requirements
* Python 3.6

## Installation
```sh
wget https://github.com/intezer/linux-explorer/archive/master.zip -O master.zip
unzip master.zip
cd linux-explorer-master
./deploy.sh
```

## Usage
1. Start your browser
```sh
firefox http://127.0.0.1:8080
```

## Configure API keys (optional)
```sh
nano config.py
```
Edit following lines:
```py
INTEZER_APIKEY = '<key>'
VT_APIKEY = '<key>'
OTX_APIKEY = '<key>'
MALSHARE_APIKEY = '<key>'
```

## Notes
* We recommend using NGINX [reverse proxy with basic http auth](https://www.nginx.com/resources/admin-guide/restricting-access-auth-basic/) & ssl for secure remote access
* Tested with Ubuntu 16.04

## Misc
* ["How to get a VirusTotal public API Key"](https://community.mcafee.com/docs/DOC-6456)
* ["To get an API Key for Intezer Analyze"](https://analyze.intezer.com/#/create-account)
