import csv
import json
import os
import sys
import requests
import base64
import argparse
import time
import warnings
import urllib3.exceptions
from termcolor import *
import colorama


# Create argparser to use in terminal
def argparser():
    parser = argparse.ArgumentParser(description='Uploads the extracted firmware files in ExtractedFirmware.csv to FACT for analysis. See https://github.com/fkie-cad/FACT_core')
    parser.add_argument('-n', '--num', default=-1, help="Amount of bytes from each file uploaded to FACT. Defaults to entire file (-1)")
    parser.add_argument('-p', '--path', default="C:\\Users\\ACI\\Desktop\\RouterFirmware", help="Base path to firmware folder")
    parser.add_argument('-s', '--server', default="https://192.168.253.129", help="Address of FACT server")
    parser.add_argument('-f', '--file', default="ExtractedFirmware.csv", help="Name of csv file to be read")
    parser.add_argument('-c', '--concurrent', default=2, type=int, help="Number of concurrent firmware extractions. Defaults to 2")
    parser.add_argument('-d', '--disable', action="store_true", help="Disables limit on concurrent firmware analysis. Recommended for small files")
    return parser.parse_args()


# Server setup
def server(server_url):
    status = None
    while status is None:
        r = requests.get("{}/rest/status".format(server_url), verify=False)
        result = json.loads(r.text)
        status = result.get('status', None)
    return result


# Setup plugins
def plugins(server_url):
    server_status = server(server_url)
    available_plugins = server_status['plugins'].keys()
    used_plugins = ['cpu_architecture', 'software_components']
    for plugin in used_plugins:
        if plugin not in available_plugins:
            print("- plugin {} not available".format(plugin))
            sys.exit(1)
    return used_plugins


# Hardcoded method to get file path, only works on paths with at most 3 backslashes
def get_file_name(row, args):
    slashes = 0
    for i in row['file_path']:
        if i == "\\":
            slashes += 1
    if slashes == 0:
        return os.path.join(args.path, row['vendor'], row['file_path'], row['file_name'])
    elif slashes == 1:
        fp1, fp2 = os.path.split(row['file_path'])
        return os.path.join(args.path, row['vendor'], fp1, fp2, row['file_name'])
    elif slashes == 2:
        temp, fp3 = os.path.split(row['file_path'])
        fp1, fp2 = os.path.split(temp)
        return os.path.join(args.path, row['vendor'], fp1, fp2, fp3, row['file_name'])
    elif slashes == 3:
        temp, fp4 = os.path.split(row['file_path'])
        temp2, fp3 = os.path.split(temp)
        fp1, fp2 = os.path.split(temp2)
        return os.path.join(args.path, row['vendor'], fp1, fp2, fp3, fp4, row['file_name'])
    else:
        print(colored("File path longer than hardcoded values. This will be incompatible with anything besides Windows", "red"))
        return "{}\\{}\\{}\\{}".format(args.path, row['vendor'], row['file_path'], row['file_name'])


# Run main analysis
def main():
    warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
    args = argparser()
    count = 1     # Count of files uploaded
    used_plugins = plugins(args.server)
    colorama.init()

    with open(args.file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Fill in basic info
            row['device_class'] = 'router'
            row['device_part'] = 'complete'
            row['requested_analysis_systems'] = used_plugins
            row['tags'] = ""
            if len(row['release_date']) == 0:
                row['release_date'] = "1970-01-01"     # Placeholder date

            # Turning binary files to base64 strings
            file_name = get_file_name(row, args)
            file = open(file_name, mode='rb').read(int(args.num))
            b64binary = base64.b64encode(file)
            row['binary'] = b64binary.decode('ascii')

            # File path was just a hardcoded column in my table for reference, not used in FACT
            del row['file_path']

            # Upload to FACT
            r = requests.put("{}/rest/firmware".format(args.server), json=row, verify=False)
            response_data = json.loads(r.text)

            status = response_data.get('status', 1)

            if status == 0:
                print(colored("Uploaded {} file(s)".format(count), "cyan"))
                count += 1
            else:
                print(r.text)
                print(colored("Failed to upload {} file".format(row["file_name"]), "red"))
                break

            if not args.disable:
                # Wait for files to join the analysis queue, so that there are no more than 2 items being analysed at once
                server_status = server(args.server)
                timer = 0
                while response_data["uid"] not in server_status["system_status"]["backend"]["analysis"]["current_analyses"]:
                    if timer % 30 == 0:
                        print("Joining queue\t|\tTime elapsed: {} seconds".format(timer))
                    time.sleep(1)
                    server_status = server(args.server)
                    timer += 1
                print(colored("Joined queue", "yellow"))
                print(colored("Total queue length: {}".format(len(server_status["system_status"]["backend"]["analysis"]["current_analyses"])), "yellow"))
                timer = 0
                while len(server_status["system_status"]["backend"]["analysis"]["current_analyses"]) >= args.concurrent:
                    if timer % 30 == 0:
                        print("Waiting for queue to process\t|\tTime elapsed: {} seconds".format(timer))
                    time.sleep(1)
                    server_status = server(args.server)
                    timer += 1
    print(colored("Finished uploading all files", "green"))


if __name__ == '__main__':
    sys.exit(main())
