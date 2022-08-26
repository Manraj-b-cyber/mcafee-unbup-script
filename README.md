# Mcafee-unbup-script

A python script to quickly unbup or extract Mcafee .Bup files and perform some automated analysis such as:
 
  1. Hashing the files (MD5, SHA256, SSDEEP)
  2. Performing strings
  3. Extracting Exif data
  4. Scanning the file with VirusTotal 
  
Some pre-requisits for this script are to have the following tools installed:
  
  1. 7zip 
  2. xortool
  3. ssdeep
  4. strings
  5. exiftool
  
Before running the script you will also need to initialise two variables:

  1. xortool_path = "PATH TO XORTOOL"
  2. Apikey = "YOUR VIRUSTOTAL API KEY HERE"

I will soon be pushing some changes to make this script less reliant on installed tools and to use libraries.
