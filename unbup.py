#!/usr/bin/python3
import os
import subprocess
import ntpath
import hashlib
import requests
import json

# Change the xortool_path variable below to the directory in which tool_xor.py resides.
# Xortool can be downloaded from https://github.com/hellman/xortool
# Also generate a VirusTotal API key and add it below to the virus_total() function

def unbup(bup_file_path):
    xortool_path = "~/Downloads/xortool/xortool/"
    os.system("7z e " + bup_file_path + " >/dev/null 2>&1")
    os.system("python3 " + xortool_path + "tool_xor.py -f Details -s 'j' > xor_Details")
    os.system("python3 " + xortool_path + "tool_xor.py -f File_0 -s 'j' > xor_File_0")
    os.system("rm Details")
    os.system("rm File_0")

    try:
        OrigonalFilePath = subprocess.check_output("cat xor_Details | grep -i OriginalName", shell=True);
        Decoded_File_Path = OrigonalFilePath.decode('utf-8')
        Stripped_File_Path = Decoded_File_Path.rstrip()
        CleanedFilePath = Stripped_File_Path.lstrip('OriginalName=')
        FileName = ntpath.basename(CleanedFilePath)
        os.rename('xor_File_0', FileName)
        return FileName

    except:
        print("We were unable to determine the name of the file")
        FileName = "xor_File_0"
        return FileName

def hashing(FileName):
    with open(FileName, "rb") as f:
        f_byte = f.read()
        hash_result = hashlib.sha256(f_byte)
        return hash_result

def static_analysis(FileName):
    strings_file = os.path.splitext(FileName)[0]
    Ssdeep_output = subprocess.check_output("ssdeep " + FileName, shell=True);
    Decoded_ssdeep = Ssdeep_output.decode('utf-8')
    Stripped_ssdeep = Decoded_ssdeep.rstrip()

    Strings_output = subprocess.check_output("strings " + FileName + " > strings_" + strings_file + ".txt", shell=True);
    Exif_output = subprocess.check_output("exiftool " + FileName + " > exif_" + strings_file + ".txt", shell=True);
    return Stripped_ssdeep, strings_file

def virus_total(hash_result):
    # VirusTotal API
    Apikey = "YOUR_API_KEY_HERE"

    Sha256 = hash_result.hexdigest()
    data = {"apikey": Apikey, "resource": Sha256}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', data=data)
    response.text

    json_data = json.loads(response.text)
    positive_scans = str(json_data["positives"])
    full_details = json_data["permalink"]
    return positive_scans, full_details

def main():
    bup_file_path = input("File path to Bup file: ")

    FileName = unbup(bup_file_path)

    hash_result = hashing(FileName)
    print("\n[+] SHA256 hash of " + FileName + " is: " + hash_result.hexdigest() + "\n")

    result = static_analysis(FileName)
    print("\n[+] The Ssdeep fuzzy hash is: " + str(result[0]))
    print("\n[+] Strings ouput has been saved to strings_" + result[1] + ".txt")
    print("\n[+] Exif ouput has been saved to exif_" + result[1] + ".txt")

    virus_result = virus_total(hash_result)
    print("\n[+] There were " + virus_result[0] + " malicious detections of this hash from Virus total")
    print("\n[+] View full detection results from Virus total at: " + virus_result[1])

if __name__ == "__main__":
    main()