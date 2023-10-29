<div align="center">
  <h1>SBounty</h1>
</div>

Sbounty is a script that leverages a combination of tools developed in bash and golang to create pipelines aimed at detecting vulnerabilities in no authenticated web applications.

This tool analyzes the routes obtained from a given URL in order to identify potential vulnerabilities, including XSS, SQLi, CORS, LFI, SSTI, Open Redirect, and SSRF.

<div align="center">
  <h2>Installation</h2>
</div>

Clone the repository and make the script executable:

```bash
git clone https://github.com/shockz-offsec/SBounty.git
cd SBounty
chmod +x sbounty.sh
```

<div align="center">
  <h3>Tools Auto-Installed</h3>
</div>

* Golang
* Gf-Patterns
* SQLMap
* waybackurls
* gf
* qsreplace
* rush
* freq
* subjack
* httpx
* gau
* hakrawler
* uro


<div align="center">
  <h2>Usage</h2>
</div>

```bash
Usage: ./sbounty.sh [-f urls_file] [-s subdomain] [-t] 
**THIS TOOL ONLY WORKS With No-Authenticated websites**
 
 TARGET OPTIONS
   -s subdomain      Live Target subdomain
   -f file           Urls file (Local Target)
 
 MODE OPTIONS
   -t                Live Subdomain Takeover - Perform a subdomain takeover check
   -h                Help - Show this help
 
 USAGE EXAMPLES
 ./sbounty.sh -f urls.txt
 ./sbounty.sh -s tesla.com
 ./sbounty.sh -s www.tesla.com
 ./sbounty.sh -s https://www.tesla.com
 
 Subdomain Takeover check:
 ./sbounty.sh -s www.tesla.com -t 
```
On the other hand, the vulnerabilities to be scanned can be enabled or disabled through the configuration file. 

In the case of SSRF, it is necessary to provide the URL of a server such as Burp Collaborator or Interactsh to receive the requests.

**config.ini**
```bash
#################################################################
#	    	        Sbounty config file			                #
#################################################################

# General values
xss=false
sqli=false
cors=false
lfi=false
ssti=false
open_redirect=false
# SSRF
ssrf=false
burpcollaborator="" # https://xx.yy.zz
#---#
```

<div align="center">
  <h2>Example</h2>
</div>

![Example](https://github.com/shockz-offsec/SBounty/assets/67438760/97dc14da-2a71-4ced-957a-1c0e5b32a9f4)

<div align="center">
  <h2>Disclaimer</h2>
</div>

This tool is designed for legal use only, such as testing and monitoring of systems that you own or have permission to test. Any other use is illegal and at your own risk. The author is not responsible for any damage caused by misuse or illegal use of this tool.

<div align="center">
  <h2>License</h2>
</div>

This tool is licensed under the GPL-3.0 License.
