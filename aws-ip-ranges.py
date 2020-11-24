# pulls specific range of IPs from AWS IP ranges.
# written January 2020 by Alex Clark

import json
import requests

url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

data = requests.get(url)
data = data.content

json_format = json.loads(data)
ip_array = []
for line in json_format['prefixes']:
    if line['service'] == 'S3' and line['region'] == 'us-east-2':
        ip_array.append(line['ip_prefix'])
		
	
aws = open('aws_ranges.txt', 'w')
    
for line in ip_array:
    aws.write("{}\n".format(line))
    
