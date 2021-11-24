import argparse
from pprint import pprint
from pymongo import MongoClient
import sys

# Referenced from the PyMongo Tutorial
#  https://pymongo.readthedocs.io/en/stable/tutorial.html


def connect():
    # Connection parameters (default for FACT)
    #   need to change the host parameter
    username = "fact_admin"
    password = "6fJEb5LkV2hRtWq0"
    host = "192.168.253.130"
    port = "27018"
    db_name = "fact_main"
    auth_db = "admin"

    mongo_uri = f"mongodb://{username}:{password}@{host}:{port}/{db_name}?authSource={auth_db}"

    # Make the connection
    client = MongoClient(mongo_uri)

    # Get a database
    db = client.fact_main

    # Get a collection
    return db.file_objects


def argparser():
    parser = argparse.ArgumentParser(
        description='Analyses software components for CVEs')
    parser.add_argument('-l', '--lookup', default="null",
                        help="Looks up all of the firmwares associated with a software component")
    parser.add_argument('-c', '--count', action="store_true",
                        help="Counts the number of CVEs associated with each file that has at least one CVE")
    parser.add_argument('-m', '--missing', action="store_true",
                        help="Counts all of the files without CVEs associated")
    return parser.parse_args()


def software_lookup(file_objects, filename):
    components = []
    for i in file_objects.find({"file_name": filename}):
        if 'cve_lookup' in i['processed_analysis'] and 'cve_results' in i['processed_analysis']['cve_lookup'] and len(
                i['processed_analysis']['cve_lookup']['cve_results']) > 0:
            for j in i['parent_firmware_uids']:
                if j not in components:
                    components.append(j)
    print("Total number of firmwares with software component \"" + filename + "\": " + str(len(components)))
    # for i in components:
    #     print(i)


def count_cve(file_objects):
    components = {}
    for i in file_objects.find():
        if 'cve_lookup' in i['processed_analysis'] and 'cve_results' in i['processed_analysis']['cve_lookup'] and len(
                i['processed_analysis']['cve_lookup']['cve_results']) > 0:
            components[i['file_name']] = len(i['processed_analysis']['cve_lookup']['cve_results'])
    print("Total number of software components with CVEs associated: " + str(len(components)))
    for i in components:
        print(i + ": " + str(components[i]))


def no_cve(file_objects):
    components = []
    for i in file_objects.find():
        if 'cve_lookup' not in i['processed_analysis'] or 'cve_results' not in i['processed_analysis']['cve_lookup'] \
                or len(i['processed_analysis']['cve_lookup']['cve_results']) == 0:
            if i['file_name'] not in components:
                components.append(i['file_name'])
    print("Total number of software components without CVEs associated: " + str(len(components)))
    for i in components:
        print(i)


def main():
    args = argparser()
    file_objects = connect()
    if args.lookup != 'null':
        software_lookup(file_objects, args.lookup)
    if args.count:
        count_cve(file_objects)
    if args.missing:
        no_cve(file_objects)
    for i in file_objects.find():
        if 'plugin_version' not in i['processed_analysis']['cpu_architecture'] or 'plugin_version' not in \
                i['processed_analysis']['file_hashes']:
            pprint(i)


if __name__ == '__main__':
    sys.exit(main())
