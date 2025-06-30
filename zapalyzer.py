#!/usr/bin/env python3

# MIT License
# 
# Copyright (c) 2024 Stefan Venz <stefan.venz@protonmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import sys
import json
import pathlib
import argparse
import requests
import time

PROCESSED_CVES = {}

def get_metrics(entry):
    """
    Parse the retrieved CVE data for it's base score and vector

    Arguments:
        entry: json data retrieved from nvd

    Returns:
        cve_data: CVE information in form "CVSS base score; CVSS vector"
    """
    cvss_vector = entry['cvssData']['vectorString']
    cvss_score = entry['cvssData']['baseScore']
    metric = f"{cvss_score};{cvss_vector}"
    return metric

def get_cve_info(cve_id, api_key=''):
    """
    Get CVE information from NVD database

    Arguments:
        cve_id: CVE identifier dictionary in form {'cveID' : 'CVE-2008-2008'}
        api_key: api key dictionary for NVD database api in form { 'apiKey' : '<apiKeyValue>'

    Returns:
        cve_data: CVE information in form "CVSS base score; CVSS vector"
    """
    cve_data = ''

    if "CVE" not in cve_id['cveId']:
        return ";"

    if not api_key:
        time.sleep(6)

    try:
        r = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                         params=cve_id, 
                         timeout=120, 
                         headers=api_key).json()
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1) 

    metrics = r['vulnerabilities'][0]['cve']['metrics']

    for metric in metrics:
        for entry in metrics[metric]:
            if entry['type'] != 'Primary':
                continue
            
            if float(entry['cvssData']['version']) > 2:
                cve_data = get_metrics(entry)
                break
        if cve_data:
            break
    else:
        cve_data = f"{get_metrics(entry)}"
            
    PROCESSED_CVES[cve_id['cveId']]  = cve_data
    return cve_data


def generate_csv_output(libs, cve_check=False, api_key=''):
    """
    Prints CSV output for vulnerable JavaScript components
    
    Arguemnts: 
        libs: list of processed alerts with id 10003
        cve_check: bool if cve data should be retrieved from NVD database
        apikey: API key for NVD database
    """
    if cve_check:
        print("host;Library;Version;Path;Issue;CVSS Base Score;CVSS Vector;Evidence")
    else:
        print("host;Library;Version;Path;Issue;Evidence")

    cve_data = ''

    for lib in libs:
        system = f"{lib['protocol']}://{lib['host']}"
        for cved in lib['issue']:
            cve = cved.strip(':')
            if len(lib['issue']) == 0:
                print(f"{system};{lib['lib']};{lib['version']};{system}/{lib['path']};{lib['lib']} {lib['version']} EoL;\'{lib['evidence'].encode()}\'")
            else:
                if cve:
                    if cve_check:
                        if cve in PROCESSED_CVES:
                            cve_data = PROCESSED_CVES[cve]
                        else:
                            cve_id = {'cveId' : cve}
                            cve_data = get_cve_info(cve_id, api_key)

                    print(f"{system};{lib['lib']};{lib['version']};{system}/{lib['path']};{cve};{cve_data};\'{lib['evidence'].encode('unicode_escape')}\'")


def parse_vulnerable_javascript(alert):
    """
    Process a single alert, for vulnerable JavaScript components
    
    The following elements will be processed for vulnerable JavaScript components
        - the vulnerable host
        - the path to the vulnerable JavaScript library
        - the library name
        - the library version
        - the alert description
        - other entries (containing CVE information if available)

    Arguments:
        alert: the individual alert entry (id: 10003)

    Returns:
        i: dictionary of the processed alert.
    """
    version = 5
    lib = 3
    i = {}

    url = alert['url'].split('/')
    desc = alert['description'].split(' ')

    i['protocol'] = url[0][:-1]
    i['host'] = url[2]
    i['path'] = '/'.join(url[3:])

    i['name'] = alert['name']
    i['cwe'] = alert['cweid']

    i['lib'] = alert['other'].split(' ')[lib].strip(',')
    #i['lib'] = desc[3][:-1]
    i['version'] = alert['other'].split(' ')[version]
    #i['version'] = desc[5]
    i['description'] = alert['description']
    i['issue'] = alert['tags']
    i['evidence'] = alert['evidence']

    return i


def parse_alert_file(alert_report):
    """
    Parse the ZAProxy JSON alert report file

    Arguments:
        alert_report: Path to the JSON alert report file

    Returns:
        libs: list of evaluated alerts
    """
    libs = []
    plid = 10003

    if (pathlib.Path(alert_report).is_file()):
        with open(alert_report, 'r') as alert_file:
            try:
                json_alerts = json.loads(alert_file.read())
            except Exception as e:
                sys.exit(f"ERROR: Failed to load report file {alert_report}: {e}")
    else:
        sys.exit(f"ERROR: {alert_report} seems to be no file")

    alerts = json_alerts['alerts']

    for alert in alerts:
        if alert['pluginId'] == str(plid):
            libs.append(parse_vulnerable_javascript(alert))

    return libs


def main():
    key = ''
    parser = argparse.ArgumentParser(
        description = "Analyze ZAProxy JSON alert report"  )
    parser.add_argument(
        '-i', '--input',
        metavar = 'file',
        help = "Path to the JSON report file",
        type = pathlib.Path,
    )
    parser.add_argument(
        '--csv',
        help = "Print the results in CSV format (default)",
        action = 'store_true',
        default = True,
    )
    parser.add_argument(
        '--nocsv',
        help = "Don't output results in CSV format",
        action = 'store_true',
        default = False,
    )
    parser.add_argument(
        '--cve',
        help = "Add CVE base score and vector to output, by performing a lookup on NIST NVD database",
        action = 'store_true',
        default = False,
    )
    parser.add_argument(
        '--apikey',
        help = "NVD database API key to speed up CVE lookup",
        metavar = '<API key>',
    )

    args = parser.parse_args()
    results = parse_alert_file(args.input)

    if args.apikey:
        key = {'apiKey' : f"{args.apikey}"}

    if args.csv and not args.nocsv:
        generate_csv_output(results, args.cve, key)


if __name__ == '__main__':
    main()

