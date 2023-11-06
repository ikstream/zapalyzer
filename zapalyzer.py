#!/usr/bin/env python3

# MIT License
# 
# Copyright (c) 2023 Stefan Venz
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

def generate_csv_output(libs):
    """
    Generate CSV output for vulnerable JavaScript components
    
    Arguemnts: 
        libs: list of processed alerts with id 10003
    """
    print("host;Library;Version;Path;Issue")

    for lib in libs:
        for cve in lib['issue'].split('\n'):
            if len(lib['issue']) == 0:
                print(f"{lib['protocol']}://{lib['host']};{lib['lib']};{lib['version']};{lib['path']};{lib['lib']} {lib['version']} EoLi")
            else:
                if cve:
                    print(f"{lib['protocol']}://{lib['host']};{lib['lib']};{lib['version']};{lib['path']};{cve}")


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
    i = {}

    url = alert['url'].split('/')
    desc = alert['description'].split(' ')

    i['protocol'] = url[0][:-1]
    i['host'] = url[2]
    i['path'] = '/'.join(url[3:])

    i['name'] = alert['name']
    i['cwe'] = alert['cweid']

    i['lib'] = desc[3][:-1]
    i['version'] = desc[5]
    i['description'] = alert['description']
    i['issue'] = alert['other']

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

    args = parser.parse_args()
    results = parse_alert_file(args.input)

    if args.csv and not args.nocsv:
        generate_csv_output(results)


if __name__ == '__main__':
    main()
