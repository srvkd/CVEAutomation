#!/bin/bash



GREEN='\033[0;32m'  # color code, use it with echo -e
NC='\033[0m'    # color code  , use it with echo -e


echo "Performing nmap scan for version detection"
nmap -sV $1 -oX output.xml # >&-    # perform version detection of the apache server and output it to a xml file

echo "Nmap scan completed"
echo -en "\n"

ports=$(xmlstarlet sel -t -v '//nmaprun/host/ports/port/@portid' output.xml)   # search for ports found in the xml file 

echo "****************************************************************************************************************************************"
echo "Found ports: " $ports


for eachProduct in $ports
do

cpe=$(xmlstarlet sel -t -v "//nmaprun/host/ports/port[@portid='$eachProduct']/service/cpe" output.xml)



for eachCpe in $cpe
do

if [[ -z $eachCpe ]] 
	then
		vendor=$(xmlstarlet sel -t -v "//nmaprun/host/ports/port[@portid='$eachProduct']/service/@name" output.xml)
		versionNumber=$(xmlstarlet sel -t -v "//nmaprun/host/ports/port[@portid='$eachProduct']/service/@version" output.xml)	
	else
	vendor=$(echo "${eachCpe:7:50}" | cut -f1 -d":")   # fetch the vendor name  
	versionNumber=$(echo "${eachCpe##*:}")                   #  fetch the version number 

	fi


# Using for loop for performing actions for each CPE found in the <cpe> tag from xml output of nmap scan 


echo -e "${GREEN}**************************************************************************************************************************************** ${NC}"

	
    
echo -e "Product: ${GREEN} $vendor ${NC} Version: ${GREEN} $versionNumber ${NC}"
echo "Calling the API https://cve.circl.lu/api/search/$vendor"
curl -s "https://cve.circl.lu/api/search/$vendor" > search1.json    # calling the api provided by CVE to search for vulnerabilities in Apache 
echo  "JSON fetch completed"
echo -en "\n"
echo -e "Displaying for ${GREEN}$eachCpe ${NC} in the vulnerable configuration"

# Display the CWE,ID,CVSS and the summary in a tabular format
echo $(jq '.data[] | select(.vulnerable_configuration_cpe_2_2 | contains(["'$eachCpe'"]))' search1.json) | jq -r '. | "\(.cwe)\t---\(.cvss)\t---\(.id)\t:\(.summary)"' | awk -v FS="," 'BEGIN{print "CWE\tCVSS\tid\t\tsummary";print "=========================================================="}{printf "%s\t%s\t%s\n",$1,$2,ORS}'
echo -en "\n"

echo -e "Finding exploits for using ${GREEN} searchsploit $vendor $versionNumber ${NC}"

searchsploit $vendor $versionNumber

echo -en "\n"

done

done

