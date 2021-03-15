#!/usr/bin/env python3

import boto3
import json
from datetime import date

output = {
    "ReportType": "AWS"
}

def find_all_s3_buckets():
    output['Buckets'] = []

    s3 = boto3.resource('s3')
    try:
        for bucket in s3.buckets.all():
            for acl in s3.BucketAcl(bucket.name).grants:
                output['Buckets'].append({"Name": bucket.name, "ACL": acl})
    except:
        output['Buckets'] = None


enabled_modules = {
    "Buckets": find_all_s3_buckets
}

for key, module in enabled_modules.items():
    print(f"Running module... {key}")
    module()

filename=f"{date.today()}_report.json"

with open(filename, "w") as outfile:
    json.dump(output, outfile)

print(f"\nReport saved to: {filename}")
