import json
import re
import sys
import os

def rule_matcher(har_file_location, rule_file_location):
	print("Running rule matcher...")

	url_rule_map = process_rules(har_file_location, rule_file_location)

	save_to_file(har_file_location, rule_file_location, url_rule_map)
	return

def traffic_change(har_file_location_1, har_file_location_2, rule_file_location):
	print("Running traffic change analyzer...")

	url_rule_map_1 = process_rules(har_file_location_1, rule_file_location)
	url_rule_map_2 = process_rules(har_file_location_2, rule_file_location)

	save_to_file(har_file_location_1, rule_file_location, url_rule_map_1)
	save_to_file(har_file_location_2, rule_file_location, url_rule_map_2)

	if not len(url_rule_map_1) == len(url_rule_map_2):
		print("Count of rules matched is different for both the HAR's")
		return

	for url in url_rule_map_1:
		if not url in url_rule_map_2:
			print("Did not find url: "+url+" in new har, mostly har is incomplete or url request/response has changed")
			return
		else:
			if not url_rule_map_1[url] == url_rule_map_2[url]:
				print("url:"+ url+" matched different rules in both har, url request/response has changed")
				return
	print("No traffic change found")
	return

def regression_check(har_file_location, old_rule_file_location, new_rule_file_location):
	print("Running regression check...")

	url_rule1_map = process_rules(har_file_location, old_rule_file_location)
	url_rule2_map = process_rules(har_file_location, new_rule_file_location)

	save_to_file(har_file_location, old_rule_file_location, url_rule1_map)
	save_to_file(har_file_location, new_rule_file_location, url_rule2_map)

	for url in url_rule1_map:
		if url not in url_rule2_map:
			print("There is no match for URL:"+url+" in new rule file, there is a regression with rule:"+url_rule1_map[url])
			return
		else:
			if not url_rule1_map[url] == url_rule2_map[url]:
				print("URL:"+url+" has matched with different rules in old and new rule file, there is a regression with rule:"+url_rule1_map[url])
				return
	print("No regression found")
	return

def save_to_file(har_file_location, rule_file_location, url_rule_map):
	har_file_name = os.path.basename(har_file_location)
	rule_file_name = os.path.basename(rule_file_location)
	out_file = open(har_file_name + "_" + rule_file_name + ".out", "w")
	print("Writing the URL's to rules matched in file : " + out_file.name)
	for url in url_rule_map:
		out_file.write(url+"\t matched "+url_rule_map[url]+"\n")
	out_file.close()
	return

def process_rules(har_file_location, rule_file_location):
	har_file = open(har_file_location, 'r')
	rule_file = open(rule_file_location, 'r')

	har_data = json.load(har_file)
	entries_list = har_data['log']['entries']

	rule_data = json.load(rule_file)

	url_rule_map = dict()
	for network_entry in entries_list:
		process_entry(network_entry, rule_data, url_rule_map)

	return url_rule_map

# Funtion to process each network call
def process_entry(network_entry, rule_data, url_rule_map):
	for rule in rule_data:
		if rule == "rule_catch_all" :
			continue
		else:
			matched = is_rule_matched(network_entry, rule_data[rule])
		if matched:
			url_rule_map[network_entry['request']['url']]=rule
			break

# Function to check if request and response of the call is matched
def is_rule_matched(network_entry, rule):
	if 'request' in rule:
		request_matched = match_request(network_entry['request'], rule['request'])
		if not request_matched:
			return False

	if 'response' in rule:
		response_matched = match_response(network_entry['response'], rule['response'])
		if not response_matched:
			return False

	return True

def match_request(http_request, rule_request):
	rule_url_list = rule_request['url']
	http_url = http_request['url']
	matched = match_value_list(rule_url_list, http_url)
	if not matched:
		return False

	header_matched = match_header(http_request, rule_request)
	if not header_matched:
		return False

	return True

'''
http_response: response object from har
rule_response: response object from rule
return True if response object for http entry from har matches with the response object from rule
'''
def match_response(http_response, rule_response):
	if 'status' in rule_response:
		rule_status_list = rule_response['status']
		http_status = str(http_response['status'])
		matched = match_value_list(rule_status_list, http_status)
		if not matched:
			return False

	header_matched = match_header(http_response, rule_response)
	if not header_matched:
		return False

	return True

'''
http_req_res: http request or response from har
rule_req_res: request or response object from rule
return True if all the headers are matching
'''
def match_header(http_req_res, rule_req_res):
	if 'headers' not in rule_req_res:
		return True

	rule_headers = rule_req_res['headers']
	for rule_header in rule_headers:
		rule_header_value_list = rule_headers[rule_header]
		http_headers_list = http_req_res['headers']
		header_found = False
		for http_header in http_headers_list:
			if http_header['name'].lower() == rule_header.lower():
				header_found = True
				matched = match_value_list(rule_header_value_list, http_header['value'])
				if not matched:
					return False
		if not header_found:
			return False

	return True

'''
rule_value_list : list of values specified in the rule
http_value : the target value to be compared with
return True if http_value matches with any of the value from rule_value_list
'''
def match_value_list(rule_value_list, http_value):
	for rule_value in rule_value_list:
		if 're:' in rule_value:	# for regex, string should start with 're:'
			matched = re.search(rule_value[3:], http_value)
			if matched:
				return True
		else :
			if rule_value == http_value:
				return True

	return False

def main():
	print("Select the tool to run:")
	print("[1] Rule Matcher")
	print("[2] Traffic Change Analyzer")
	print("[3] Rule Regression Analyzer")
	option = raw_input("Select the tool [1|2|3]:")
	if option == "1":
		har_file_location = raw_input("Enter HAR file location:")
		rule_file_location = raw_input("Enter Rule file location:")
		rule_matcher(har_file_location, rule_file_location)
	if option == "2":
		har_file_location_1 = raw_input("Enter old HAR file location:")
		har_file_location_2 = raw_input("Enter new HAR file location:")
		rule_file_location = raw_input("Enter Rule file location:")
		traffic_change(har_file_location_1, har_file_location_2, rule_file_location)
	if option == "3":
		har_file_location = raw_input("Enter HAR file location:")
		old_rule_file_location = raw_input("Enter Old Rule file location:")
		new_rule_file_location = raw_input("Enter New Rule file location:")
		regression_check(har_file_location, old_rule_file_location, new_rule_file_location)

if __name__ == "__main__":
	main()
