# python3 ip-info.py 8.8.8.8

# add alien vault
# add virustotal
"""
AbuseIPDB_API_KEY = key['ABUSEIPDB_API_KEY'] #abuseipdb
apility_key = key['APILITY_API_KEY'] #apility #apility.io
app_ipgeolocation_key = key['APP_IPGEOLOCATION_API_KEY'] #ipgeolocation api.ipgeolocation.io
blacklist_key = key['BLACKLIST_MASTER_API_KEY'] #blacklistmaster #blacklistmaster.com
cisco_investigate_token = key['CISCO_INVESTIGATE_TOKEN'] #cisco investigate
blacklist_username = key['BLACKLIST_MASTER_API_USERNAME'] #blacklistmaster #blacklistmaster.com
"""


#map:

# try and except for each 
# assigned empty string for each variables
# one variable for each json object



from datetime import date
from requests import get
from sys import argv
import requests
import socket
import json
import csv
import os 

keys_json = json.load(open('ip_config.json', 'r')) # import config file
key = keys_json['keys']
#print(key)

ip = argv[1]

AbuseIPDB_API_KEY = key['ABUSEIPDB_API_KEY']
apility_key = key['APILITY_API_KEY']
app_ipgeolocation_key = key['APP_IPGEOLOCATION_API_KEY']
blacklist_key = key['BLACKLIST_MASTER_API_KEY']
cisco_investigate_token = key['CISCO_INVESTIGATE_TOKEN']
blacklist_username = key['BLACKLIST_MASTER_API_USERNAME']

profile = os.getenv('USERPROFILE')
path_to_file = f"{profile}\desktop\ip.html"
file = open(path_to_file,"w")
file.write(f"<br><br>{ip}")
file.write("<br><br>Whois<br>")


def whois(item):
    ''' Apility + ipapi '''
    ''' returns Json '''
	
    print("Whois\n")
	
    ''' Apility geo location information '''
    try:
        geo_function = json.loads(json.dumps(returns_json(query_type_geo,item)))
    except:
        print("error with geo_function")
    
    ''' Apility asn '''
    try:
        version_one_as_json = json.loads(json.dumps(returns_json(version_one_as,item)))
    except:
        print("error with version_one_as_json")

    ''' Apility whois info '''
    try:
        whois_info = json.loads(json.dumps(returns_json(query_type_whois_info,item)))
    except:
        print("error with whois_info")

    ''' IPAPI '''    
    try:
        json_info_country = get('https://ipapi.co/%s/country_name/' % item).text
        json_info_region = get('https://ipapi.co/%s/region/' % item).text
        json_info_city = get('https://ipapi.co/%s/city/' % item).text
    except:
        print("error with ipapi")

    ''' api.ipgeolocation.io '''
    try:
        ipgeo = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={app_ipgeolocation_key}&ip={item}")
        json_ipgeo = json.loads(ipgeo.content.decode("utf-8"))
        print(f"\n\tIPGeolocation.io:    Continent::      {json_ipgeo['continent_name']}")
        print(f"\tIPGeolocation.io:    Country::        {json_ipgeo['country_name']}")
        print(f"\tIPGeolocation.io:    Country Code::   {json_ipgeo['country_code2']}")
        print(f"\tIPGeolocation.io:    State, Prov::    {json_ipgeo['state_prov']}")
        print(f"\tIPGeolocation.io:    City::           {json_ipgeo['city']}")
        print(f"\tIPGeolocation.io:    ISP::            {json_ipgeo['isp']}")
        print(f"\tIPGeolocation.io:    Organization::   {json_ipgeo['organization']}")
        file.write(f"<br>\n\tIPGeolocation.io:    Continent::      {json_ipgeo['continent_name']}\n")
        file.write(f"<br>\tIPGeolocation.io:    Country::        {json_ipgeo['country_name']}\n")
        file.write(f"<br>\tIPGeolocation.io:    Country Code::   {json_ipgeo['country_code2']}\n")
        file.write(f"<br>\tIPGeolocation.io:    State, Prov::    {json_ipgeo['state_prov']}\n")
        file.write(f"<br>\tIPGeolocation.io:    City::           {json_ipgeo['city']}\n")
        file.write(f"<br>\tIPGeolocation.io:    ISP::            {json_ipgeo['isp']}\n")
        file.write(f"<br>\tIPGeolocation.io:    Organization::   {json_ipgeo['organization']}\n")
    except:
        print("error with api.ipgeolocation.io")
		


    '''Abuse IPDB '''
    ''' returns status and confidence score for a domain or IP '''
    endpoint  = 'https://api.abuseipdb.com/api/v2/check'
    query_string = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': 'yes'
    }

    headers = {
        'Accept': 'application/json',
        'key': AbuseIPDB_API_KEY
    }
    try:
        response = requests.get(url=endpoint, headers=headers, params=query_string)
        abuse_ipdb_json_result = json.loads(response.content)
        print(f"\n\tAbuseIPDB:           Country Name::   {abuse_ipdb_json_result['data']['countryName']}")
        print(f"\tAbuseIPDB:           Country Code::   {abuse_ipdb_json_result['data']['countryCode']}")
        print(f"\tAbuseIPDB:           ISP::            {abuse_ipdb_json_result['data']['isp']}")	
        print(f"\tAbuseIPDB:           Domain::         {abuse_ipdb_json_result['data']['domain']}")
        file.write(f"<br><br>\tAbuseIPDB:           Country Name::   {abuse_ipdb_json_result['data']['countryName']}")
        file.write(f"<br>\tAbuseIPDB:           Country Code::   {abuse_ipdb_json_result['data']['countryCode']}")
        file.write(f"<br>\tAbuseIPDB:           ISP::            {abuse_ipdb_json_result['data']['isp']}")
        file.write(f"<br>\tAbuseIPDB:           Domain::         {abuse_ipdb_json_result['data']['domain']}")		

    except:
        print("error with abuseipdb")
        abuse_ipdb_json_result = "error"
	



    try:
        print(f"\n\tApility:             Continent Name:: {geo_function['ip']['continent_names']['en']}")
        print(f"\tApility:             Country::        {version_one_as_json['as']['country']}")
        print(f"\tApility:             Time Zone::      {geo_function['ip']['time_zone']}")
        print(f"\tApility:             Network Cidr::   {whois_info['whois']['network']['cidr']}")
        print(f"\tApility:             Networks::       {version_one_as_json['as']['networks']}")
        print(f"\tApility:             AS Name::        {version_one_as_json['as']['name']}")
        print(f"\n\tIpapi:               Country::        {json_info_country}")						# united Stateeprint
        print(f"\tIpapi:               Region::         {json_info_region}")							# 21202
        print(f"\tIpapi:               City::           {json_info_city}")                           # Los Angeles
        file.write(f"<br><br>\tApility:             Continent Name:: {geo_function['ip']['continent_names']['en']}")
        file.write(f"<br>\tApility:             Country::        {version_one_as_json['as']['country']}")
        file.write(f"<br>\tApility:             Time Zone::      {geo_function['ip']['time_zone']}")
        file.write(f"<br>\tApility:             Network Cidr::   {whois_info['whois']['network']['cidr']}")
        file.write(f"<br>\tApility:             Networks::       {version_one_as_json['as']['networks']}")
        file.write(f"<br>\tApility:             AS Name::        {version_one_as_json['as']['name']}")
        file.write(f"<br><br>\tIpapi:               Country::        {json_info_country}")
        file.write(f"<br>\tIpapi:               Region::         {json_info_region}")
        file.write(f"<br>\tIpapi:               City::           {json_info_city}")
    except:
        print("Error with Apility and or IPAPI")
	
    return abuse_ipdb_json_result


def blacklist_multi(item, abuse_ipdb_json_result):


  
	
    print("\n\nReputation\n")
    file.write(f"<br><br>\tReputation\n")	


    ''' Blacklist Master '''
    ''' returns minimal info regarding blacklist status '''
    score = ' '
    try:
        blacklist = get('https://www.blacklistmaster.com/restapi/v0/blacklistcheck/ip/%s' % item, auth=(blacklist_username, blacklist_key)).text
        blacklist_json_format = json.loads(blacklist)
        status = blacklist_json_format["status"]
        if status == 'Not blacklisted':
            count = ' '
        else:
            count = blacklist_json_format["blacklist_cnt"]
        print(str(f"\n\tBlacklistmaster::    {status} {count}"))
        file.write(f"<br><br>\tBlacklistmaster::    {status} {count}")
    except:
        print("error with blacklist master")	

    ''' printing apility blacklist results '''
    try:
        print(f"\n{blacklist_apility}") # returns 'blacklisted by apility' or 'not blacklisted by apility'
        file.write(f"<br>\t{blacklist_apility}")
    except:
        print("error printing Apility Blacklist info")




    ''' printing abuseipdb results '''		
    try:
        print(f"\n\tAbuseIPDB:     Whitelisted::          {abuse_ipdb_json_result['data']['isWhitelisted']}")
        print(f"\tAbuseIPDB:     Total Reports::        {abuse_ipdb_json_result['data']['totalReports']}")
        print(f"\tAbuseIPDB:     Confidence of Abuse::  {abuse_ipdb_json_result['data']['abuseConfidenceScore']}\n")
        file.write(f"<br><br>\tAbuseIPDB:     Whitelisted::          {abuse_ipdb_json_result['data']['isWhitelisted']}")
        file.write(f"<br>\tAbuseIPDB:     Total Reports::        {abuse_ipdb_json_result['data']['totalReports']}")
        file.write(f"<br>\tAbuseIPDB:     Confidence of Abuse::  {abuse_ipdb_json_result['data']['abuseConfidenceScore']}\n")
    except:
        print("Error printing AbuseIPDB results")
		
    ''' Cisco Investigate '''

    headers = {
        'Authorization': 'Bearer ' + cisco_investigate_token
    }
    try:
        investigate_response = requests.get(f'https://investigate.api.umbrella.com/ips/{item}/latest_domains', headers=headers)
        investigate_json = json.loads(investigate_response.content.decode("utf-8"))
        print(f"\n\tCisco Investigate: Latest Malicious Domains Associated with this IP address:\n\t {investigate_json}")
        file.write(f"<br>\tCisco Investigate: Latest Malicious Domains Associated with this IP address:\n\t {investigate_json}")
    except:
        print("error with cisco investigate")
		
    try:
        threat_miner = requests.get(f"https://api.threatminer.org/v2/host.php?q={item}&rt=4")
        print(f"\tThreat Miner: Related Samples::\t {threat_miner.content}")
        file.write(f"<br>\tThreat Miner: Related Samples::\t {threat_miner.content}")
    except:
        print("error with threatminer")
        print(f"Threat Miner response code {threat_miner.status_code}")
        file.write("Error with Threat Miner")





  

########################################################################################
# Apility below

# Apility scan type variables
blacklist_checker = 'badip'             #  blacklist
query_type_whois_info = 'whois/ip'      #  whois
query_type_geo = 'geoip'                #  geo info
version_one_as = 'as/ip'                #  asn info

############### functions for all Apility API calls -BENEATH THIS LINE- ########################

def blacklist(query_type,input):
    ''' checks if IP is found in Apility's blacklist '''
    ''' returns 404 error if it was not found in a blacklist '''
    ''' returns 200 OK if it was found in blacklist '''
    url = 'https://api.apility.net/%s/%s' % (query_type,input)
    headers = {'X-Auth-Token': apility_key}
    try:
        http_response_code = str(requests.get(url, headers=headers))
        if http_response_code == '<Response [404]>':
            http_response_code = "\tBlacklist Apility:: Not Blacklisted"
            return http_response_code
        else:
            http_response_code = "\tBlacklist Apility:: Blacklisted"
            return http_response_code
    except:
        print("error with Apility Blacklist")


def returns_json(query_type,input):
    ''' checks multiple different types of calls and returns json '''
    call = requests.get('https://api.apility.net/%s/%s' % (query_type,input), headers={
        "Accept": "application/json",
        "X-Auth-Token": apility_key
    })
    return call.json()

############### functions for all Apility API calls -ABOVE THIS LINE- ########################



''' Apility checks blacklist and returns http status code '''
blacklist_apility = str(blacklist(blacklist_checker,ip))



print("\n%s\n" % ip) 
whois_info = whois(ip) # line[0] = IP

blacklist_multi(ip, whois_info)



os.system(f"powershell.exe start-process chrome {path_to_file}")
