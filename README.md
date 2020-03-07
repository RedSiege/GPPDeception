# GPPDeception
This script generates a groups.xml file that mimics a real GPP to create a new user on domain-joined computers.  

Blue teams can use this file as a <a href="https://blog.code42.com/using-honey-files-to-stop-data-exfiltration/">honeyfile</a>. 
By monitoring for access to the file, Blue Teams can detect pen testers or malicious actors scanning for GPP files containing usernames
and cpasswords for lateral movment.  

Blue Teams can also monitor for use of the credentials as <a href="https://www.sans.org/reading-room/whitepapers/attacking/catching-flies-guide-flavors-honeypots-36897"honeycreds</a>.

# Usage
Invoke-GPPDeception -Plaintext plaintextpassword -UserName honeycredaccount
