# written by Alex Clark Summer 2019
# submits a url to be scanned by both Urlscan.io and Virustotal, then grabs a screenshot from screenshotlayer * note there have been inconsistencies in screenshots, likely due to presence of javascript on site.
# usage -> python web-scan.py


from datetime import datetime
from time import sleep
import urllib.parse
import requests
import json
import time


def virus_total_report_submission(url_to_scan):
    ''' submits URL to Virus-Total for analysis '''
    api_key = 'virustotal-apikey'
    params = {'apikey': api_key, 'url': url_to_scan, 'scan':'1'}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params) # submits scan to virus total
    return response.json()

	
def urlscan_io_report_submission(url_to_scan):	
    ''' submits URL to urlscan.io '''
    global uuid_variable	
    headers = {
        'Content-Type': 'application/json',
        'API-Key': 'urlscan-apikey',
        }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "public": "on" }' % url_to_scan).json() # submits scan to urlscan.io
    uuid_variable = str(response['uuid']) # uuid, this is the factor that identifies the scan for urlscan.io
    return uuid_variable # return uuid
	
	
def submit_all_reports():
    ''' submits reports to urlscan.io and virus total '''
    global url_to_scan # defining variable as global	
    url_to_scan = str(input("\nEnter the domain you'd like to scan: ")) # URL for scanning
    virus_total_report_submission(url_to_scan) # submits URL to Virus-Total for analysis
    urlscan_io_report_submission(url_to_scan) # submits URL to urlscan.io for analysis
    screenshotlayer(url_to_scan) # call function to get screenshot
    print('\nNow scanning %s. Check back in around 1 minute.' % url_to_scan) # writing to console
    sleep(45) # sleeps for 45 seconds while scans are run
	
	
def virus_total_report_retrieval(url_to_scan):
    ''' retrieves URL analysis from Virus-Total '''
    api_key = 'virustotal-apikey'
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }
    params = {'apikey': api_key, 'resource':url_to_scan}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
      params=params, headers=headers)
    return response.json()


def report_virus_total_verdict(report):
    ''' prepares verdict for screen printing '''
    global resource
    positives = report['positives'] # number of scan engines deeming it malicious 
    resource = report['url'] # site name
    total = report['total'] # total number of scan engines
    print('\n\nVerdict of scan %s:\n\n\n' % resource)
    if positives == 0:
        scan_result_word = 'clean'
    elif positives == '0':
        scan_result_word = 'clean'
    else:
        scan_result_word = 'malicious'

    Virus_Total_results = 'Virus-Total: %s - detected by %d/%d scan engines' % (scan_result_word, positives, total)
    return Virus_Total_results


def retrieve_screenshot_from_urlscan_io():
    ''' retrieves screenshot from Urlscan.io '''
    global uuid_variable
    global resource
    response = requests.get('https://urlscan.io/screenshots/%s.png' % uuid_variable) # retrieving screenshot
    scan_time = str(datetime.today().strftime('%Y-%m-%d')) # getting time stamp and site name ready to title the image.
    file_name_resource = ''.join(e for e in resource if e.isalnum())

    try:
        file_name = str('%s-%s-scan.png' % (scan_time, file_name_resource))
    except:
        file_name = str('%s-scan.png' % (scan_time))

    with open('%s' % file_name, 'wb') as code:
        code.write(response.content) # writing the screenshot to this file.




def screenshotlayer(url_to_scan):
    '''retrieve screenshot from screenshotlayer '''
    access_key = "screenshot layer apikey" # key for screenshot layer.com
    dictionary = { 'url' : url_to_scan, 'format' : 'PNG' }
    url_var = urllib.parse.urlencode(dictionary)
    print('{%s}' % url_to_scan)
    print(url_var)
	# http://api.screenshotlayer.com/api/capture?access_key=721bf1903e7bf10126ee66b8a9f36bc0&url=castillolawsb.com%2Ftomandjerry2%2Fa2&format=PNG
    answer = requests.get("https://api.screenshotlayer.com/api/capture?access_key=%s&%s" % (access_key, url_var))
    file_name_resource = ''.join(e for e in url_to_scan if e.isalnum())
    scan_time = str(datetime.today().strftime('%Y-%m-%d')) # getting time stamp and site name ready to title the image.
    try:
        with open('%s-%s.png' % scan_time, file_name_resource, 'wb') as code:
            code.write(answer.content) # writing the screenshot to this file	
    except:
        with open('%s-screenshot.png' % scan_time,  'wb') as code:
            code.write(answer.content) # writing the screenshot to this file		


		
def urlscan_io_report_retrieval():
    ''' retrieves report from urlscan.io '''
    global uuid_variable
    scan_results = requests.get('https://urlscan.io/api/v1/result/%s/' % uuid_variable).json() # retrieving the scan using the uuid for this scan
    try:
        urlscan_results = scan_results['stats']['malicious'] # particular json item that was important to me
    # retrieve_screenshot_from_urlscan_io() # retrieves screenshot from urlscan.io -> commenting out screenshot from urlscan.io
    except:
        urlscan_results = scan_results
    if urlscan_results == 0:
        site_status = "\nUrlscan.io: clean"
    else:
        site_status = "\nUrlscan.io: malicious"
    return site_status

	

def main():
    ''' scans url for malware and reputation '''
    ''' Urlscan.io '''
    ''' Virus Total '''
    global url_to_scan
    submit_all_reports() # submits all reports	
    print(report_virus_total_verdict(virus_total_report_retrieval(url_to_scan))) # prints Virus-Total verdict to screen
    print(urlscan_io_report_retrieval()) # prints Urlscan.io verdict to screen

    print('\n\n\nYou\'ll find a screenshot of the homepage in the directory you ran this script from.\n')

	
if __name__ == '__main__':
    main()


