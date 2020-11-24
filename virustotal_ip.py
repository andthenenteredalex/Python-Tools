# 4-23-2019 by Alex Clark
#updated 10/2020

# usage python virustotal-ip.py 8.8.8.8

# https://www.virustotal.com/en/documentation/public-api/





# error with 151.243.145.201 # FIX THAT


# 2 ERROR HANDLING CODE
#    a. if [] -> no response means nothing found 
#    b. if [{some item}, {some other item}, {some third item}] -> loop while item[0], item[1]. item[2] etc. maybe use len(json_response[item]) ?
# 3 REPORTS
# 4 INTEGRATION


import json
import requests
from sys import argv
from datetime import *


now = datetime.now()
past_ninety = datetime.now() - timedelta(days=90)



key = 'virustotal_apikeyy'
#ip = '8.8.8.8'

ip = argv[1]

def ip_reputation_info(api_key,ip):
    ' ' 'checks reputation on IP address ' ' '
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': ip, 'apikey': api_key}

    response = requests.get(url, params=params).json()
 
    #print(response)                       # entire json
    
    ### info 
    
    # print(response['response_code'])      # 1
    # print(response['asn'])                # 4134
    #print(response['continent'])          # AS
    # print(response['whois'])              # entire whois
    # print(response['network'])            # 115.238.224.0/19
    #print(response['country'])            # prints CN   
    #print(response['continent'])          # AS
    #print(response['as_owner'])           # No.31, Jin-rong Street    
    # print(response['whois_timestamp'])    # 1554890699
    # print(response['verbose_msg'])       # IP address in dataset


    ##########################################################
          # THE FOLLOWING DOMAINS RESOLVE TO THE GIVEN IP ADDRESS  
    
    # detected = detected by scan engines = 'malicious'
    # undetected = not detected by any scan engines = 'clean'  
     
    # EDIT
	
	# new for 8-11-2020
    print("\nPassive DNS domains:\n")
    for i in response['resolutions']:
        print(i['last_resolved'] + "  " + i['hostname'])
    # end new for 8-11-2020
		
		
    domains = []
    try:
        total_domains = len(response['resolutions'])
        #print(total_domains)
        if total_domains >= 1:
            for i in response['resolutions']:
                #print(i['last_resolved'])
                date_one = i['last_resolved']
                if datetime.fromisoformat(date_one) >= past_ninety:
                    domains.append(i['hostname'])
                else:
                    pass
        elif total_domains == 0:
            domains.append('zero')
        else:
            print(len(response['resolutions']))
			
    except:
        print("There was an error in the resolutions branch")
        print(response) # response['resolutions']
    
    if len(domains) > 1:
        print("Domains resolved last 90 days:")
        for l in domains:
            print(l)
    elif len(domains) == 0:
        print("No domains resolved in the last 90 days")
    else:
        print(domains)


    ##########################################################
             # LATEST URLS SCANNED THAT WERE HOSTED AT THIS IP ADDRESS 
    
    # detected = detected by scan engines = 'malicious'

    try:
        if len(response['detected_urls']) != 0:
            #print(len(response['detected_urls']))
            print("Malicious URLs scanned in last 90 days:")
            for i in response['detected_urls']:
                date_one = i['scan_date']
                if datetime.fromisoformat(date_one) >= past_ninety:
                    print(f"URL: {i['url']}")
                    print(f"\tScan Date: {i['scan_date']} - Score: {i['positives']}\\{i['total']}")

        elif len(response['detected_urls']) == 0:
            print("No malicious URLs")
    except:
        print("Error, hitting the exception branch.")
        print(response)
		

    # undetected = not detected by any scan engines = 'clean'		
		
			
    try:
        if len(response['undetected_urls']) != 0:
            #print(len(response['undetected_urls']))
            print("Clean URLs scanned in last 90 days:")
            for i in response['undetected_urls']: # ['http://1544.ir/', 'd1e4a091df6a1d0a9cf3f1dd215fa7f98c295179b8ef9318bbfe1992d43e41bb', 0, 76, '2020-03-25 12:55:41']
                date_one = i[4]
                if datetime.fromisoformat(date_one) >= past_ninety:
                    print(f"URL: {i[0]} Scan Date: {i[4]}")
						
        elif len(response['undetected_urls']) == 0:
            print("No clean URLs")
    except:
        print("Error, hitting the exception branch.")
        print(response)


    ###########################################################
                # LATEST FILES DOWNLOADED FROM THIS IP

    # detected = detected by scan engines = 'malicious'
    # undetected = not detected by any scan engines = 'clean'

    # print(response['detected_downloaded_samples']) # [{'positives': 1, 'sha256': 'a7d973ceaf69770fc2390921ea605dd7ed7ee5292b9626b4299c5b502c6af496', 'total': 48, 'date': '2013-11-29 07:57:24'}]
    # print(response['detected_downloaded_samples'][0]['positives'])  # 1
    # print(response['detected_downloaded_samples'][0]['sha256'])     # a7d973ceaf69770fc2390921ea605dd7ed7ee5292b9626b4299c5b502c6af496
    # print(response['detected_downloaded_samples'][0]['total'])      # 48 
    # print(response['detected_downloaded_samples'][0]['date'])       # 2013-11-29 07:57:24
 
    # print(response['undetected_downloaded_samples']) # [{'positives': 0, 'sha256': '22e9027bbf1096db85f493d6edd63b22c685f1bca1f5096dc7a8ca7fb282adbd', 'total': 46, 'date': '2014-03-05 14:35:36'}]
    # print(response['undetected_downloaded_samples'][0]['positives'])  # 0
    # print(response['undetected_downloaded_samples'][0]['sha256'])     # 22e9027bbf1096db85f493d6edd63b22c685f1bca1f5096dc7a8ca7fb282adbd
    # print(response['undetected_downloaded_samples'][0]['total'])      # 46
    # print(response['undetected_downloaded_samples'][0]['date'])       # 2014-03-05 14:35:36
    


    #########################################################
            # FILES WHERE THIS IP FOUND IN CONTENTS

    # detected = detected by scan engines = 'malicious'
    # undetected = not detected by any scan engines = 'clean'

    # print(response['detected_referrer_samples']) # []  ####### --->>>> if response is [] : nothing was found.
    
    # print(response['detected_referrer_samples'][0]['positives'])    
    # print(response['detected_referrer_samples'][0]['sha256'])    
    # print(response['detected_referrer_samples'][0]['total'])
    # print(response['detected_referrer_samples'][0]['date'])
            
    # print(response['undetected_referrer_samples']) # [{'positives': 0, 'sha256': '4472e66e2cf8d68d441091f20a6a489d0ca88e718a189414be93006d1938c2a4', 'total': 70, 'date': '2019-04-09 09:58:57'}]
    # print(response['undetected_referrer_samples'][0]['positives']) # 0
    # print(response['undetected_referrer_samples'][0]['sha256'])    # 4472e66e2cf8d68d441091f20a6a489d0ca88e718a189414be93006d1938c2a4
    # print(response['undetected_referrer_samples'][0]['total'])     # 70
    # print(response['undetected_referrer_samples'][0]['date'])      # 2019-04-09 09:58:57
    
    #######################################################


	
	
ip_reputation_info(key,ip)

