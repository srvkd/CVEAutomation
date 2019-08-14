# CVEAutomation
Automated CVE detection with NMAP

This shell script runs the NMAP on a target and saves the output in a XML file. This output XML is treated as an input and the datasource for CPE numbers that are found. Based on this CPE numbers, the CVE online APIs are called and searched if there is a CVE present for this particular CPE number. Further, using searchspoilt it fetches the possible exploits.


Arguments
- IP address of the target

Prerequisites
- It requires 2 libraries on Kali machine. 'JQ' and 'XMLstarlet'

Install them by running these commands
1)  sudo apt-get install jq
2) sudo apt-get install xmlstarlet
