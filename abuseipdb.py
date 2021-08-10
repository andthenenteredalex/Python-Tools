""" In progress. Going to accept commandline argument for IP address and what type of info desired in response. """


# python3
# AbuseIPDB

API_KEY = "XXXXXXXXXXXYOURKEYXXXXXXXXXX"

from sys import argv
import requests
import json


#### begin check
endpoint  = 'https://api.abuseipdb.com/api/v2/check'

address = argv[1]

query_string = {
    'ipAddress': f'{address}',
    'maxAgeInDays': '90',
    'verbose': 'yes'
}

headers = {
    'Accept': 'application/json',
    'key': API_KEY
}

#response = requests.get(url=endpoint, headers=headers, params=query_string)


#json_result = json.loads(response.content)
#print(json_result)
#print(json_result['data'])
#print(json_result['data']['ipAddress'])
#print(json_result['data']['isPublic'])
#print(json_result['data']['ipVersion'])
#print(json_result['data']['isWhitelisted'])
#print(json_result['data']['abuseConfidenceScore'])
#print(json_result['data']['countryCode'])
#print(json_result['data']['countryName'])
#print(json_result['data']['usageType'])
#print(json_result['data']['isp'])
#print(json_result['data']['domain'])
#print(json_result['data']['domain'])
#print(json_result['data']['totalReports'])
#print(json_result['data']['numDistinctUsers'])
#print(json_result['data']['lastReportedAt'])
#print(json_result['data']['reports'])


### end check




###report functionality not needed by client. Will write if needed.


##### begin check block


endpoint = "https://api.abuseipdb.com/api/v2/check-block"

query_string = {
    'network':'127.0.0.1/24',
    'maxAgeInDays':'15'
}

headers = {
    'Accept': 'application/json',
    'Key':  API_KEY
}

#response = requests.get(url=endpoint, headers=headers, params=query_string)

#jj = json.loads(response.content)
#print(jj['data'])
#print(jj['data']['networkAddress'])
#print(jj['data']['netmask'])
#print(jj['data']['minAddress'])
#print(jj['data']['maxAddress'])
#print(jj['data']['numPossibleHosts'])
#print(jj['data']['addressSpaceDesc'])
#print(jj['data']['reportedAddress'])

#### end check block

### bulk report functionality not needed by client.
