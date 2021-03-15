#!/usr/bin/env python3

import os
import sys
import json
import inspect
from datetime import date

print("| |   (_)_ __  _   ___  __   ___ ___ | | | ___  ___| |_ ___  _ __ ")
print("| |   | | '_ \| | | \ \/ /  / __/ _ \| | |/ _ \/ __| __/ _ \| '__|")
print("| |___| | | | | |_| |>  <  | (_| (_) | | |  __/ (__| || (_) | |   ")
print("|_____|_|_| |_|\__,_/_/\_\  \___\___/|_|_|\___|\___|\__\___/|_|   ")
print("                                                       by Traficom")
if(os.geteuid() != 0):
    print("Please run this script as root!")
    exit(1)

output = {
    "ReportType": "LINUX"
}


def kernelparams():
    output['KernelParams'] = []
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            ip_forward = bool(f.read())
    except:
        ip_forward = None

    output['KernelParams'].append({'KernelIpForward': ip_forward})


def list_superusers():
    output['Superusers'] = []
    try:
        with open('/etc/passwd') as f:
            for line in f:
                splitted_line = line.replace('\n', '').split(":")

                if int(splitted_line[2]) == 0:
                    output['Superusers'].append({'Username': splitted_line[0],
                                            'Shell': splitted_line[6],
                                            'GroupId': int(splitted_line[3]),
                                            'UserId': int(splitted_line[2])
                                            })
    except:
        output['Superusers'] = None

def find_all_suid_files():
    output['SUIDFiles'] = []
    print("This will take while...")
    files = os.popen('find / -perm /4000 2>/dev/null')
    for line in files.readlines():
        output['SUIDFiles'].append({"file": line.replace('\n','')})

enabled_modules = {
    "Kernel params": kernelparams,
    "List superusers": list_superusers,
    "Find all suid files": find_all_suid_files
}

for key, module in enabled_modules.items():
    print(f"Running module... {key}")
    module()

filename=f"{date.today()}_report.json"

with open(filename, "w") as outfile:
    json.dump(output, outfile)

print(f"\nReport saved to: {filename}")
