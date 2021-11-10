import csv
import json
import os
import sys
import requests
import base64
import argparse
import time
import warnings

import termcolor
import urllib3.exceptions


# Not using termcolor right now, did not get it to work in terminal
from termcolor import colored
import colorama

def argparser():
    # Create argparser to use in terminal
    parser = argparse.ArgumentParser(description='Uploads the extracted firmware files in ExtractedFirmware.csv to FACT for analysis. See https://github.com/fkie-cad/FACT_core')
    parser.add_argument('-n', '--n', default=-1, help="Amount of bytes from each file uploaded to FACT. Defaults to entire file (-1)")
    parser.add_argument('-p', '--p', default="C:\\Users\\ACI\\Desktop\\RouterFirmware", help="Base path to firmware folder")
    parser.add_argument('-s', '--s', default="https://192.168.253.129", help="Address of FACT server")
    parser.add_argument('-f', '--f', default="ExtractedFirmware.csv", help="Name of csv file to be read")
    return parser.parse_args()


def server():
    # Server setup
    args = argparser()
    r = requests.get(os.path.join("{}/rest/status".format(args.s)), verify=False)
    return json.loads(r.text)


def plugins():
    # Setup plugins
    server_status = server()
    available_plugins = server_status['plugins'].keys()
    used_plugins = ['cpu_architecture', 'software_components']
    for plugin in used_plugins:
        if plugin not in available_plugins:
            print("- plugin {} not available".format(plugin))
            sys.exit(1)
    return used_plugins


def main():
    warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
    args = argparser()
    count = 1     # Count of files uploaded
    used_plugins = plugins()
    colorama.init()

    #with open('server_status.json', 'w') as ssj:
    #    ssj.write(json.dumps(server()))
    #sys.exit(0)

    with open(args.f, newline='') as csvfile:
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
                file_name = os.path.join("{}\\{}\\{}\\{}".format(args.p, row['vendor'], row['file_path'], row['file_name']))
                file = open(file_name, mode='rb').read(int(args.n))
                b64binary = base64.b64encode(file)
                row['binary'] = b64binary.decode('ascii')

                # File path was just a hardcoded column in my table for reference, not used in FACT
                del row['file_path']

                # Upload to FACT
                r = requests.put(os.path.join("{}/rest/firmware".format(args.s)), json=row, verify=False)
                response_data = json.loads(r.text)

                if "status" in response_data:
                    status = response_data['status']
                else:
                    status = 1
                    print(r.text)

                if status == 0:
                    print(colored("Uploaded {} file(s)".format(count), "cyan"))
                    count += 1
                else:
                    print(colored("Failed to upload {} file".format(row["file_name"]), "red"))
                    break

                unpackingStatus = requests.get(os.path.join("{}/rest/status".format(args.s)), verify=False)
                unpackingStatusJ = json.loads(unpackingStatus.text)
                qcount = 0
                while response_data["uid"] not in unpackingStatusJ["system_status"]["backend"]["analysis"]["current_analyses"]:
                    if qcount % 30 == 0:
                        print("Joining queue\tTime elapsed: {} seconds".format(qcount))
                    time.sleep(1)
                    unpackingStatus = requests.get(os.path.join("{}/rest/status".format(args.s)), verify=False)
                    unpackingStatusJ = json.loads(unpackingStatus.text)
                    qcount += 1
                print(colored("Joined queue", "yellow"))
                print(colored("Total queue length: {}".format(len(unpackingStatusJ["system_status"]["backend"]["analysis"]["current_analyses"])), "yellow"))
                qcount = 0
                while len(unpackingStatusJ["system_status"]["backend"]["analysis"]["current_analyses"]) >= 2:
                    if qcount % 30 == 0:
                        print("Waiting for queue to process\tTime elapsed: {} seconds".format(qcount))
                    time.sleep(1)
                    unpackingStatus = requests.get(os.path.join("{}/rest/status".format(args.s)), verify=False)
                    unpackingStatusJ = json.loads(unpackingStatus.text)
                    qcount += 1
        print(colored("Finished uploading all files", "green"))


if __name__ == '__main__':
    sys.exit(main())
