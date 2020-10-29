''' 
___________________________________________________________________________________

	Title: DIMA DEV - Phishing Predictions Wireframe
	Purpose: This file has rules functions to get the dataset ready for ml model
	Author: DIMA Business Solutions Team - 2019-20
	Required Files: 1. abused_words.txt and domains_list.txt
___________________________________________________________________________________

'''

#Importing Python Packges: 
import random
from bs4 import BeautifulSoup
from termcolor import colored


#rule: 01
import re

#rule: 05
import socket
import ssl
import datetime

#rule: 06
import whois

#rule: 07
import favicon
import tldextract

#rule: 09
import urllib.request, sys
import xmltodict, json

#rule: 10
import requests



#rule: 16
import dns.resolver


#rule: 17
from urllib.parse import urlencode


print(colored('''
	_______________________________________________________________

		Title: DIMA AI-ML Engine - Phishing Predictions							
		Purpose: This file has rules functions to get the dataset ready for ml model 														
		Author: DIMA Business Solutions Team - 2019-20
		Results Calibration:
		1. if ouput is 1 ------> PHISHING
		2. if ouput is 0 ------> SUSPICIOUS
		3. if ouput is -1 ------> LEGITIMATE
		Total Rules: 10					
	_______________________________________________________________

	''', 'yellow'))

# results list



user_agent_list = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]

for i in range(1,4):
	#Pick a random user agent
	user_agent = random.choice(user_agent_list)

#Set the headers 
headers = {'User-Agent': user_agent}

'''
----------------------------------------------------------------------------------
Rule 00: Gathering requirements and data
----------------------------------------------------------------------------------
Including: 
1. Regex rule for ip for IPv4
2. Set the headers with random user agent
3. Scrap webpage 
4. Domain Extraction with tldextract
----------------------------------------------------------------------------------
'''
#1. Regex rule for ip for IPv4

regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''


#2. Set the headers with random user agent
user_agent_list = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]

for i in range(1,4):
	#Pick a random user agent
	user_agent = random.choice(user_agent_list)


headers = {'User-Agent': user_agent}

#3. Scrap webpage
def scrap_webpage(query):
	print("Results for ",query)
	print("-"*50)
	try:
		url = "http://"+query
		scrap_webpage.request_chk = requests.get(url, allow_redirects=True, headers=headers, timeout=5)
		webdata = scrap_webpage.request_chk	
		scrap_webpage.html = webdata.content
	except:
		scrap_webpage.html = ""


def extract_final_domain(text):
	import tldextract
	info = tldextract.extract(text)
	domain_name = info.domain
	suffix_name = info.suffix
	final_domain_name  = domain_name+"."+suffix_name
	return final_domain_name


'''
----------------------------------------------------------------------------------
Rule 01: using raw ip address
----------------------------------------------------------------------------------
1. If The Domain Part has an IP Address ---> Phishing ----> 1
2. otherwise ---> Legitimate ----> -1
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def using_ip_address(query):
	if(re.search(regex, query)): 
		print("using_ip_address: ", 1)
		final_result.append(1)		
	else: 
		print("using_ip_address: ", -1)
		final_result.append(-1)

'''
----------------------------------------------------------------------------------
Rule 02: Long Domain to Hide the Suspicious Part
----------------------------------------------------------------------------------
1. Domain length < 15 ---> Legitimate ----> -1
2. Domain length >= 15 and <= 30 ---> Suspicious -----> 0
3. otherwise ---> Phishing ----> 1
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def using_long_domain(query):
	if len(query) < 10:
		print("url_length: ",-1)
		final_result.append(-1)
	elif len(query)>=10 and len(query)<=30:
		print("url_length: ",0)
		final_result.append(0)
	else:
		print("url_length: ",1)
		final_result.append(1)

'''
----------------------------------------------------------------------------------
Rule 03: Adding Prefix or Suffix Separated by (-) to the Domain
----------------------------------------------------------------------------------
1. If - dash symbol is in domain ---> Phishing ----> 1
2. otherwise ---> Legitimate ----> -1
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def using_dash_symbol(query):
	if "-" in query:
		print("using_dash_symbol: ",1)
		final_result.append(1)
	else:
		print("using_dash_symbol: ",-1)
		final_result.append(-1)

'''
----------------------------------------------------------------------------------
Rule 04: Sub Domain and Multi Sub Domains
----------------------------------------------------------------------------------
1. If domain part (dots in domain) = 1 ---> Legitimate ----> -1
2. If domain part (dots in domain) = 2 ---> Suspicious -----> 0
3. otherwise ---> Phishing ----> 1
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def multi_sub_domains(query):
	dot_numbers = 0
	for i in query:
		if "."==i:
			dot_numbers += 1
	if dot_numbers==1:
		print("multi_sub_domains: ",-1)
		final_result.append(-1)
	elif dot_numbers==2:
		print("multi_sub_domains: ",0)
		final_result.append(0)
	else:
		print("multi_sub_domains: ",1)
		final_result.append(1)
'''
----------------------------------------------------------------------------------
Rule 05: HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer) 
----------------------------------------------------------------------------------
1. If ssl certificate with verified issuer ---> Legitimate ----> -1
2. otherwise ---> Phishing ----> 1
----------------------------------------------------------------------------------
Output: (1,  -1)
----------------------------------------------------------------------------------
'''

def ssl_checker(query):
	ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'
	now = datetime.datetime.now()
	context = ssl.create_default_context()
	context.check_hostname = False

	conn = context.wrap_socket(
	    socket.socket(socket.AF_INET),
	    server_hostname=query,
	)
	conn.settimeout(5.0)
	# 5 second timeout
	try:
		conn.connect((query, 443))

		ssl_info = conn.getpeercert()
		# print(ssl_info)
		# Python datetime object
		expire = datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)
		diff = expire - now
		if diff.days > 0:
			print("ssl_checker: ",-1)
			final_result.append(-1)
		else:
			print("ssl_checker: ",0)
			final_result.append(0)
	except:
		print("ssl_checker: ",1)
		final_result.append(1)

'''
----------------------------------------------------------------------------------
Rule 06: Domain Registration Period length
----------------------------------------------------------------------------------
1. Domain expires on > 1 year ---> Legitimate ----> -1
2. otherwise ---> Phishing ----> 1 (Below 1 year and below period is suspicious)
----------------------------------------------------------------------------------
Output: (1,  -1)
----------------------------------------------------------------------------------
'''

def domain_age(query):
	try:
		domain = whois.query(query)
		exp = domain.expiration_date
		cre = domain.creation_date
		diff = exp -cre
		domain_age=int(diff.days/365)
		if domain_age > 1:
			print("domain_age: ",-1)
			final_result.append(-1)
		else:
			print("domain_age: ",1)
			final_result.append(1)
	except:
		print("domain_age: ",1)
		final_result.append(1)

'''
----------------------------------------------------------------------------------
Rule 07: Favicon - loads from same domain or not
----------------------------------------------------------------------------------
1. Domain loads a favicon from same domain ---> Legitimate ----> -1
2. Domain does not load favicon ---- > 0
3. Domain loads a favicon from external domain ---> Phishing ----> 1 

----------------------------------------------------------------------------------
Output: (1, 0 -1)
----------------------------------------------------------------------------------
'''
def favicon(query):
	import favicon
	import re
	import tldextract
	try:
		url = "http://"+query
		icons = favicon.get(url, timeout=2, headers=headers)
		is_favicon = len(icons)
		if is_favicon != 0:
			text = icons[0].url
			info = tldextract.extract(text)
			domain_name = info.domain
			suffix_name = info.suffix
			final_domain_name  = domain_name+"."+suffix_name
			if final_domain_name == query:
				print("favicon: ",-1)
				final_result.append(-1)
			else:
				print("favicon: ",1)
				final_result.append(1)
		else:
			print("favicon: ",0)
			final_result.append(0)
	except:
		print("favicon: ",0)
		final_result.append(0)



'''
----------------------------------------------------------------------------------
Rule 08: The Existence of “HTTPS” Token in the Domain Part
----------------------------------------------------------------------------------
1. Domain doesn't have "HTTPS" in domain ---> Legitimate ----> -1
2. Otherwise ---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''
def https_spoof(query):
	if "https" in query:
		print("https_spoof: ",1)
		final_result.append(1)
	else:
		print("https_spoof: ",-1)
		final_result.append(-1)

'''
----------------------------------------------------------------------------------
Rule 09: Alexa Ranking
----------------------------------------------------------------------------------
1. Domain in rank below 2000000 ---> Legitimate ----> -1
2. Otherwise ---> Phishing ----> 1
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def alexa_ranking_check(query):
	try:
		xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(query)).read()
		result= xmltodict.parse(xml)
		data = json.dumps(result).replace("@","")
		data_tojson = json.loads(data)
		rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
		if rank < 2000001:
			print("alexa_ranking_check: ",-1)
			final_result.append(-1)
		else:
			print("alexa_ranking_check: ",1)
			final_result.append(1)
	except:
		print("alexa_ranking_check: ",1)
		final_result.append(1)
'''
----------------------------------------------------------------------------------
Rule 10: webpage such as images, videos and sounds are loaded from another domain
----------------------------------------------------------------------------------
1. % of Request URL loads from same Domain < 22 % ---> Legitimate ----> -1
2. % of Request URL loads from same Domain < 22 % and > 61 % -----> Suspicious ---> 0
3. Otherwise ---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def request_url(query):
	matched_real = 0
	not_matched = 0
	try:
		html = scrap_webpage.html
		html = html.decode("utf-8")
		#use re.findall to get all the links
		links = re.findall('"((http|ftp)s?://.*?)"', html)
		total_domains = len(links)
		for i in links:
			text = i[0]
			extract_final_domain(text)

			if final_domain_name == query:
				matched_real += 1
			else:
				not_matched += 1
		not_match_percentage = (not_matched/total_domains)*100
		if not_match_percentage < 22:
			print("request_url: ",-1)
			final_result.append(-1)
		elif 22 < not_match_percentage < 61:
			print("request_url: ",0)
			final_result.append(0)
		else:
			print("request_url: ",1)
			final_result.append(1)
	except:
		print("request_url: ",0)
		final_result.append(0)

'''
----------------------------------------------------------------------------------
Rule 11: Empty anchor links in website : "#", "#content", "#skip", "JavaScript ::void(0)"
----------------------------------------------------------------------------------
1. % of Empty anchor links < 31 % ---> Legitimate ----> -1
2. % of Empty anchor links >= 31 % and <= 67 %-----> Suspicious ---> 0
3. Otherwise ---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''
def link_of_anchor(query):
	try:
		empty_anchor_links = []
		html = scrap_webpage.html
		html = html.decode("utf-8")
		soup = BeautifulSoup(html, 'html.parser')
		# soup = BeautifulSoup(r.text, 'html.parser')
		total_links = soup.find_all('a', href=True)
		unlink_anchor = ["#", "#content", "#skip", "JavaScript ::void(0)"]
		for link in total_links:
			if link['href'] in unlink_anchor:
				empty_anchor_links.append(link['href'])
		empty_links_percentage = (len(empty_anchor_links)/len(total_links))*100
		if empty_links_percentage < 31:
			print("link_of_anchor: ",-1)
			final_result.append(-1)
		elif 31 <= empty_links_percentage <= 67:
			print("link_of_anchor: ",0)
			final_result.append(0)
		else:
			print("link_of_anchor: ",1)
			final_result.append(1)
	except:
		print("link_of_anchor: ",1)
		final_result.append(1)

'''
----------------------------------------------------------------------------------
Rule 12: Server Form handler --- domain and mail to 
----------------------------------------------------------------------------------
1. If Server Form handler actions is Same domain ---> Legitimate ----> -1
2. If Server Form handler actions are to different domain----> Suspicious ---> 0
3. If server form handler actions are blank or using MAILTO: ---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''
def server_form_handler(query):
	try:
		html = scrap_webpage.html
		html = html.decode("utf-8")
		soup = BeautifulSoup(html, 'html.parser')
		if soup.find_all("form"):
			for i in soup.find_all("form"):
				action = i.attrs.get("action").lower()
				if action not in ["", "about:blank"]:
					info = tldextract.extract(action)
					domain_name = info.domain
					suffix_name = info.suffix
					final_domain_name  = domain_name+"."+suffix_name
					if final_domain_name in [query, "."]:
						print("server_form_handler: ",-1)
						final_result.append(-1)
					else :
						print("server_form_handler: ",0)
						final_result.append(0)

				elif "mailto" in action:
					print("server_form_handler: ",1)
					final_result.append(1)

				else:
					print("server_form_handler: ",1)
					final_result.append(1)
		else:
			print("server_form_handler: ",0)
			final_result.append(0)
	except:
		print("server_form_handler: ",0)
		final_result.append(0)

'''
----------------------------------------------------------------------------------
Rule 13: Website Forwarding 
----------------------------------------------------------------------------------
1. If website redirects max 2 times or lesser than that ---> Legitimate ----> -1
2. If website redirects 3 or more times but lesser than 4----> Suspicious ---> 0
2. If website redirects more than---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def website_forwarding(query):
	try:
		request_chk = scrap_webpage.request_chk
		redir_dest_count = len(request_chk.history)
		if redir_dest_count <= 2:
			print("website_forwarding: ",-1)
			final_result.append(-1)
		elif 3 >= redir_dest_count < 4:
			print("website_forwarding: ",0)
			final_result.append(0)
		else:
			print("website_forwarding: ",1)
			final_result.append(1)
	except:
		print("website_forwarding: ",0)
		final_result.append(0)


'''
----------------------------------------------------------------------------------
Rule 14: Disabling Right Click checker
----------------------------------------------------------------------------------
1. If webpage does not have right click disabled ---> Legitimate ----> -1
2. finds nothing -----> Suspicious --- 0
3. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def right_click_disabled(query):
	try:
		html = scrap_webpage.html
		if "oncontextmenu" in html:
			if 'oncontextmenu="return false;' in html:
				print("right_click_disabled: ",1)
				final_result.append(1)
			else:
				print("right_click_disabled: ",0)
				final_result.append(0)
		else:
			print("right_click_disabled: ",-1)
			final_result.append(-1)
	except:
		print("right_click_disabled: ",0)
		final_result.append(0)


'''
----------------------------------------------------------------------------------
Rule 15: Iframe and iframeborder check
----------------------------------------------------------------------------------
1. If webpage does not have iframe ---> Legitimate ----> -1
2. find iframe but with iframeborder = 1 -----> Suspicious --- 0
3. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, 0, -1)
----------------------------------------------------------------------------------
'''

def iframeborder_check(query):
	try:
		html = scrap_webpage.html
		if "iframe" in html:
			if 'frameborder="0"' in html:
				print("iframeborder_check: ",1)
				final_result.append(1)
			else:
				print("iframeborder_check: ",0)
				final_result.append(0)
		else:
			print("iframeborder_check: ",-1)
			final_result.append(-1)
	except:
		print("iframeborder_check: ",0)
		final_result.append(0)

'''
----------------------------------------------------------------------------------
Rule 16: Check DNS Record 
----------------------------------------------------------------------------------
1. If domain has dns records ---> Legitimate ----> -1
2. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def dns_record_check(ele):
	try:
		answers = dns.resolver.resolve(ele,'NS')
		dns_records_count = len(answers)
		if dns_records_count == 0:
			print("dns_record_check: ",1)
			final_result.append(1)
		else:
			print("dns_record_check: ",-1)
			final_result.append(-1)
	except:
		print("dns_record_check: ",1)
		final_result.append(1)

'''
----------------------------------------------------------------------------------
Rule 17: Check google indexing
----------------------------------------------------------------------------------
1. If domain is indexed in google ---> Legitimate ----> -1
2. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def google_index_check(query):
	url = "http://"+ query
	google_Search = {'q': 'info:' + url}
	google = "https://www.google.com/search?" + urlencode(google_Search)
	try:
		data = requests.get(google, headers=headers)
		html = data.content
		soup = BeautifulSoup(html, "html.parser")
		check = soup.find(id="rso").find("div").find("div")
		check = str(check)
		if query in check:
			print("google_index_check: ",-1)
			final_result.append(-1)
		else: 
			print("google_index_check: ",1)
			final_result.append(1)
	except:
		print("google_index_check: ",0)
		final_result.append(0)

'''
----------------------------------------------------------------------------------
Rule 18: Check digits count in domain
----------------------------------------------------------------------------------
1. If domain has less than 4 digits ---> Legitimate ----> -1
2. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def digit_char_check(query):
	digit_char = [int(i) for i in query if i.isdigit()]
	if len(digit_char) < 4:
		print("digit_char_check: ",-1)
		final_result.append(-1)
	else:
		print("digit_char_check: ",1)
		final_result.append(1)


'''
----------------------------------------------------------------------------------
Rule 19: Check phishing abusive words in domain
----------------------------------------------------------------------------------
1. If domain does not have abusive phishing keyword ---> Legitimate ----> -1
2. Otherwise---> Phishing ----> 1 
----------------------------------------------------------------------------------
Output: (1, -1)
----------------------------------------------------------------------------------
'''

def abused_phishing_words_check(query):
	abused_keywords = [line.strip() for line in open("abused_words.txt", 'r')]
	split_query = query.split('.')
	abused_keywords_set = set(abused_keywords)
	split_query_set = set(split_query)
	if len(abused_keywords_set.intersection(split_query_set)) > 0:
		print("abused_phishing_words_check: ",1)
		final_result.append(1)
	else:
		print("abused_phishing_words_check: ",-1)
		final_result.append(-1)
		
	


######################################

if __name__ == '__main__':
	query_set = [line.strip() for line in open("domain_list.txt", 'r')]
	phishing_domains_list = []
	legitimate_domains_list = []
	for ele in query_set:
		final_result=[]
		scrap_webpage(ele)
		using_ip_address(ele)
		using_long_domain(ele)
		using_dash_symbol(ele)
		multi_sub_domains(ele)
		ssl_checker(ele)
		domain_age(ele)
		favicon(ele)
		https_spoof(ele)
		alexa_ranking_check(ele)
		request_url(ele)
		link_of_anchor(ele)
		server_form_handler(ele)
		website_forwarding(ele)
		right_click_disabled(ele)
		iframeborder_check(ele)
		dns_record_check(ele)
		google_index_check(ele)
		digit_char_check(ele)
		abused_phishing_words_check(ele)
		print("="*100)
		phishing_score = 0
		for i in final_result:
			if i== 1:
				phishing_score += 1

		phishing_score = phishing_score/len(final_result)*10
		phishing_score = round(phishing_score, 2)
		print("PHISHING SCORE: ", phishing_score, "/10")
		if phishing_score > 2:
			print(colored('xxxxxxxxxxxxxx Predicted as PHISHING xxxxxxxxxxxxxx', 'red'))
			phishing_domains_list.append(ele)
		else:
			print(colored('************** Predicted as LEGITIMATE **************', 'green'))
			legitimate_domains_list.append(ele)
		print("="*100)

	print("Phishing domains are: ", colored(phishing_domains_list, 'red'))
	print("="*100)
	print("Legitimate domains are: ", colored(legitimate_domains_list, 'green'))
	print("="*100)