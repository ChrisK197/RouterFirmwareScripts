import argparse
import re
import warnings

from pprint import pprint
from pymongo import MongoClient
from collections import defaultdict
import sys

# Referenced from the PyMongo Tutorial
#  https://pymongo.readthedocs.io/en/stable/tutorial.html


def argparser():
    parser = argparse.ArgumentParser(
        description='Analyses software components for CVEs')
    parser.add_argument('-l', '--lookup', default="null",
                        help="Looks up all of the firmwares associated with a software component")
    parser.add_argument('-c', '--count', action="store_true",
                        help="Counts the number of CVEs associated with each file that has at least one CVE")
    parser.add_argument('-m', '--missing', action="store_true",
                        help="Counts all of the files without CVEs associated")
    parser.add_argument('-e', '--example', default=None,
                        help="Find example of software with CVE associated.")
    return parser.parse_args()


def connect():
    # Connection parameters (default for FACT)
    #   need to change the host parameter
    username = "fact_admin"
    password = "6fJEb5LkV2hRtWq0"
    host = "192.168.253.128"
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


def software_lookup(file_objects, filename):
    components = []
    query = re.compile(".*(?i){}.*".format(filename))
    for i in file_objects.find({"file_name": query}):
        if 'cve_lookup' in i['processed_analysis'] and 'cve_results' in i['processed_analysis']['cve_lookup'] and len(
                i['processed_analysis']['cve_lookup']['cve_results']) > 0:
            for j in i['parent_firmware_uids']:
                if j not in components:
                    components.append(j)
    print("Total number of firmwares with software component \"" + filename + "\": " + str(len(components)))
    # for i in components:
    #     print(i)


def count_cve(file_objects):
    field = "processed_analysis.software_components.summary"
    query = {"processed_analysis.cve_lookup.summary": {"$exists": True, "$not": {"$size": 0}}}
    data = file_objects.distinct(field, query=query)
    unique = defaultdict(int)
    zero_cves = set()
    for i in data:
        data2 = file_objects.find({"processed_analysis.software_components.summary": i,
                                   "processed_analysis.cve_lookup.cve_results": {"$not": {"$size": 0}}})
        for j in data2:
            if 'cve_lookup' not in j['processed_analysis']:
                # print(j['processed_analysis']['software_components']['summary'])
                continue
            results = j['processed_analysis']['cve_lookup']['cve_results']
            if isinstance(results, str):
                continue
            if len(results) == 0:
                zero_cves.update(j['processed_analysis']['software_components']['summary'])
                continue
            elem = i.strip().rsplit(' ', 1)[0]
            # results is a single element dictionary with the name of the software component as the key and a
            # dictionary of CVEs as the value. Thus, results[list(results)[0]] is the dictionary of CVEs
            if len(results[list(results)[0]]) > unique[elem]:
                unique[elem] = len(results[list(results)[0]])
    for i in unique:
        print("{}: {}".format(i, unique[i]))
    print("Count CVE -- total number with CVEs: {}".format(len(unique)))
    # print(zero_cves)
    '''
    components = {}
    for i in file_objects.find():
        if 'cve_lookup' in i['processed_analysis'] and 'cve_results' in i['processed_analysis']['cve_lookup'] and len(
                i['processed_analysis']['cve_lookup']['cve_results']) > 0:
            components[i['file_name']] = len(i['processed_analysis']['cve_lookup']['cve_results'])
    print("Total number of software components with CVEs associated: " + str(len(components)))
#    for i in components:
#       print(i + ": " + str(components[i]))
    '''


def alt_count_cve(file_objects):
    query = {"processed_analysis.cve_lookup.summary": {"$exists": True, "$not": {"$size": 0}}}
    data = file_objects.find(query)
    unique = set()
    for i in data:
        for j in i['processed_analysis']['software_components']['summary']:
            unique.add(j.split(' ')[0])
    print(unique)
    print("alt0 -- total number with CVEs {}".format(len(unique)))
    return unique


def alt2_count_cve(file_objects):
    field = "processed_analysis.cve_lookup.summary"
    data = file_objects.distinct(field)
    unique = set(i.strip().split(' ')[0] for i in data)
    print(unique)
    print("alt2 -- total number with CVEs {}, unique {}".format(len(data), len(unique)))
    return unique


def alt3_count_cve(file_objects):
    field = "processed_analysis.software_components.summary"
    query = {"processed_analysis.cve_lookup.summary": {"$not": {"$size": 0}}}
    data = file_objects.distinct(field, query=query)
    unique = set(i.strip().split(' ')[0] for i in data)
    print(unique)
    print("alt3 -- total number with CVEs {}, unique {}".format(len(data), len(unique)))
    return unique


def no_cve(file_objects):
    components = []
    for i in file_objects.find():
        if 'cve_lookup' not in i['processed_analysis'] or 'cve_results' not in i['processed_analysis']['cve_lookup'] \
                or len(i['processed_analysis']['cve_lookup']['cve_results']) == 0:
            if i['file_name'] not in components:
                components.append(i['file_name'])
    print("Total number of software components without CVEs associated: " + str(len(components)))
    # pprint(components)
    # for i in components:
    # print(i)


def alt_no_cve(file_objects):
    field = "processed_analysis.software_components.summary"
    query = {"processed_analysis.cve_lookup.summary": {"$size": 0}}
    data = file_objects.distinct(field, query=query)
    unique = set(i.strip().split(' ')[0] for i in data)
    print(data)
    print("alt -- total number without CVEs {}, unique {}".format(len(data), len(unique)))
    return unique


def print_example_file(file_objects, software):
    re_str = re.compile(r".*{}.*".format(software))
    query = {"processed_analysis.cve_lookup.summary": re_str}
    data = file_objects.find_one(query)
    pprint(data)


def main():
    warnings.filterwarnings('ignore', category=DeprecationWarning)
    args = argparser()
    file_objects = connect()
    if args.lookup != 'null':
        software_lookup(file_objects, args.lookup)
    if args.count:
        # alt3_count_cve(file_objects)
        count_cve(file_objects)
        '''
        c1 = alt_count_cve(file_objects)
        c2 = alt2_count_cve(file_objects)
        c3 = alt3_count_cve(file_objects)
        m = set()
        for i in c1:
            if i not in c2 or i not in c3:
                m.add(i)
        for i in c2:
            if i not in c1 or i not in c3:
                m.add(i)
        for i in c3:
            if i not in c1 or i not in c2:
                m.add(i)
        print(m)
        '''
    if args.missing:
        alt_no_cve(file_objects)
        # no_cve(file_objects)
    if args.example is not None:
        print_example_file(file_objects, args.example)


if __name__ == '__main__':
    sys.exit(main())
