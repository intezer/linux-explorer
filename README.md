# Linux Expl0rer
Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask.

![Alt Text](https://github.com/intezer/linux-explorer/raw/master/image.gif)

## Capabilities
### ps
* View full process list
* Inspect process memory map & fetch memory strings easly
* Dump process memory in one click
* Automaticly search hash in public services
  * [VirusTotal](https://www.virustotal.com/#/home/upload)
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
* Python 2.7
* YARA
* chkrootkit

## Installation
1. Clone repository
```sh
git clone https://github.com/intezer/linux_expl0rer
```

2. Install required packages
```sh
pip install -r requirements.txt
```

3. Setup VT/OTX api keys(optional)
```sh
nano config.py
```
Edit following lines:
```py
VT_APIKEY = '<key>'
OTX_APIKEY = '<key>'
MALSHARE_APIKEY = '<key>'
```
4. Install YARA
```sh
sudo apt-get install yara
```
5. Install chkrootkit
```sh
sudo apt-get install chkrootkit
```

## Start Linux Expl0rer server
```sh
sudo python linux_explorer.py
```

## Usage
1. Start your browser
```sh
firefox http://127.0.0.1:8080
```
2. do stuff

## Notes
* We recommend using NGINX [reverse proxy with basic http auth](https://www.nginx.com/resources/admin-guide/restricting-access-auth-basic/) & ssl for secure remote access
* Tested with Ubuntu 16.04

## Misc
* ["How to get a VirusTotal public API Key"](https://community.mcafee.com/docs/DOC-6456)
