import csv
import json
import sys
import requests
import base64
import argparse
import time
import warnings
import urllib3.exceptions
from pathlib import Path, PureWindowsPath
import hashlib
from termcolor import *
import colorama


# Create argparser to use in terminal
def argparser():
    parser = argparse.ArgumentParser(
        description='Uploads the extracted firmware files in ExtractedFirmware.csv to FACT for analysis. '
        'See https://github.com/fkie-cad/FACT_core')
    parser.add_argument('-n', '--num', default=-1,
                        help="Amount of bytes from each file uploaded to FACT. Defaults to entire file (-1)")
    parser.add_argument('-p', '--path', default="C:\\Users\\ACI\\Desktop\\RouterFirmware",
                        help="Base path to firmware folder")
    parser.add_argument('-s', '--server', default="https://192.168.253.129",
                        help="Address of FACT server")
    parser.add_argument('-f', '--file', default="ExtractedFirmware.csv",
                        help="Name of csv file to be read")
    parser.add_argument('-c', '--concurrent', default=2, type=int,
                        help="Number of concurrent firmware extractions. Defaults to 2")
    parser.add_argument('-d', '--disable', action="store_true",
                        help="Disables limit on concurrent firmware analysis. Recommended for small files")
    return parser.parse_args()


# Server setup
def server(server_url):
    status = None
    result = ""
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


# Taken from FACT_Core API
def create_uid(input_data: bytes) -> str:
    '''
    generate a UID (unique identifier) SHA256_SIZE for a byte string containing data (e.g. a binary)
    :param input_data: the data to generate the UID for
    :return: a string containing the UID
    '''
    hash_value = hashlib.sha256(input_data).hexdigest()
    if isinstance(input_data, bytes):
        size = len(input_data)
    if isinstance(input_data, str):
        size = len(input_data.encode('utf-8'))
    else:
        size = len(bytes(input_data))
    return '{}_{}'.format(hash_value, size)


# Loops until a spot opens in the queue, based on the allowed concurrency
def queueloop():
    args = argparser()
    server_status = server(args.server)
    queue = server_status["system_status"]["backend"]["analysis"]["current_analyses"]
    timer = 0

    print(colored("Total queue length: {}".format(len(queue)), "yellow"))
    while len(queue) >= args.concurrent:
        if timer % 30 == 0:
            print("Waiting for queue to process\t|\tTime elapsed: {} seconds".format(timer))
        time.sleep(1)
        server_status = server(args.server)
        queue = server_status["system_status"]["backend"]["analysis"]["current_analyses"]
        timer += 1


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

            # Open binary file
            file_name = PureWindowsPath("{}\\{}\\{}\\{}".format(
                args.path, row['vendor'], row['file_path'], row['file_name']))
            correct_path = Path(file_name)
            file = open(correct_path, mode='rb').read(int(args.num))

            # Checking if file is already being analyzed
            uid = create_uid(file)
            u = requests.get("{}/rest/firmware/{}".format(args.server, uid), verify=False)
            u_text = json.loads(u.text)
            u_status = u_text['status']
            if u_status == 0:
                print(colored("Already uploaded file {}: ".format(count), "cyan") +
                      colored("{} {} v.{} ({}), \"{}\"".format(
                          row['vendor'], row['device_name'], row['version'], row['release_date'], row['file_name']),
                          "magenta"))
                server_status = server(args.server)
                queue = server_status["system_status"]["backend"]["analysis"]["current_analyses"]
                if count >= args.concurrent:
                    queueloop()
                count += 1
                continue

            # Turning binary files to base64 strings
            b64binary = base64.b64encode(file)
            row['binary'] = b64binary.decode('ascii')

            # File path was just a hardcoded column in my table for reference, not used in FACT
            del row['file_path']

            # Upload to FACT
            r = requests.put("{}/rest/firmware".format(args.server), json=row, verify=False)
            response_data = json.loads(r.text)

            status = response_data.get('status', 1)

            if status == 0:
                print(colored("Uploaded file {}: ".format(count), "cyan") +
                      colored("\"{}\"".format(row['file_name']), "magenta"))
                count += 1
            else:
                print(r.text)
                print(colored("Failed to upload file {}: ".format(row["file_name"]), "red") +
                      colored("{} {} v.{} ({}), \"{}\"".format(
                          row['vendor'], row['device_name'], row['version'], row['release_date'], row['file_name']),
                          "magenta"))
                break

            if not args.disable:
                # Wait for files to join analysis queue, so that there are no more than 2 items being analysed at once
                server_status = server(args.server)
                timer = 0
                queue = server_status["system_status"]["backend"]["analysis"]["current_analyses"]
                while response_data["uid"] not in queue:
                    if timer % 30 == 0:
                        print("Joining queue\t|\tTime elapsed: {} seconds".format(timer))
                    time.sleep(1)
                    server_status = server(args.server)
                    queue = server_status["system_status"]["backend"]["analysis"]["current_analyses"]
                    timer += 1
                print(colored("Joined queue", "yellow"))
                queueloop()
    print(colored("Finished uploading all files", "green"))


if __name__ == '__main__':
    sys.exit(main())
