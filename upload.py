import csv
import json
import sys
import requests
import base64
import argparse

# Not using termcolor right now, did not get it to work in terminal
from termcolor import colored

# Create argparser to use in terminal
# Take bytes to be uploaded as a parameter, default to all
parser = argparse.ArgumentParser(description='Uploads the extracted firmware files in ExtractedFirmware.csv to FACT for analysis. See https://github.com/fkie-cad/FACT_core')
parser.add_argument('-n', '--n', default=-1, help="Amount of bytes from each file uploaded to FACT. Defaults to entire file (-1)")
args = parser.parse_args()

# VMware running FACT locally
server_url = "https://192.168.253.129"

# General file path
base_path = "C:\\Users\\ACI\\Desktop\\RouterFirmware"

# Server setup
r = requests.get("{}/rest/status".format(server_url), verify=False)
server_status = json.loads(r.text)

# Setup plugins
available_plugins = server_status['plugins'].keys()
used_plugins = ['cpu_architecture', 'software_components']
for plugin in used_plugins:
    if plugin not in available_plugins:
        print("- plugin {} not available".format(plugin))
        sys.exit(1)

count = 1     # Count of files uploaded

with open('ExtractedFirmware.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        if row['vendor'] != '':     # Not needed anymore, since blank lines were removed later
            # Fill in basic info
            row['device_class'] = 'router'
            row['device_part'] = 'complete'
            row['requested_analysis_systems'] = used_plugins
            row['tags'] = ""
            if len(row['release_date']) == 0:
                row['release_date'] = "1970-01-01"     # Placeholder date

            # Turning binary files to base64 strings
            file_name = "{}\\{}\\{}\\{}".format(base_path, row['vendor'], row['file_path'], row['file_name'])
            file = open(file_name, mode='rb').read(int(args.n))
            b64binary = base64.b64encode(file)
            row['binary'] = b64binary.decode('ascii')

            # File path was just a hardcoded column in my table for reference, not used in FACT
            del row['file_path']

            # Upload to FACT
            r = requests.put("https://192.168.253.129/rest/firmware", json=row, verify=False)
            response_data = json.loads(r.text)
            if "status" in response_data:
                status = response_data['status']
            else:
                status = 1
                print(r.text)
            if status == 0:
                print("Uploaded {} file(s)".format(count))
                count += 1
            else:
                print("Failed to upload {} file".format(row["file_name"]))
                break
    print("Finished uploading all files")