import email
import re,sys
import argparse
from colorama import Fore, Back, Style
import sys

from colorama import init as color_init

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib

#Reading the command line arguments
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("-f","--file",type=str)
args=arg_parser.parse_args()

# Reading the file Need to take the file as command line arguments argparse
file_data = open(args.file)
email_message = email.message_from_file(file_data)
file_data.close()

#Retrieving the email headers 
email_parser = email.parser.HeaderParser()
email_headers = email_parser.parsestr(email_message.as_string())

#Initializing the values
checks={
	"message_id":"",
	"spf_record":False,
	"dkim_record":False,
	"dmarc_record":False,
	"ip_address":"",
	"sender_client":"",
	"date_time":"",
	"content_type":"",
	"subject":"",
    "sender":"",
    "org_record":""    
}

#A redirect is a pointer to another domain name that hosts an SPF policy shared by many. This function checks for the redirect domain.
def redirect_check_for_spf(spf):
    redirect = spf.get_redirect_domain()
    if redirect is not None:
        return check_spf_strength(redirect)
    else:
        return False

# include mechanism specifies other domains that are authorized domains.
def include_mec_check_for_spf(spf):
    
    list_include = spf.get_include_domains()
    for include in list_include:
        string_strength = check_spf_strength(include)
        if string_strength:
            return True

    return False

#checks if spf redirect record mechanism strong or not!
def redirect_strong_spf(spf):
    
    redirect_strength = spf._is_redirect_mechanism_strong()
    return redirect_strength

#checks if spf include mechanisms strong or not!
def include_strong_spf(spf):

    include_strength = spf._are_include_mechanisms_strong()
    return include_strength

#checks if both redirect and inculde mechanisms are strong 
def redirect_include_check(spf):
    strength_of_other_records = False
    if spf.get_redirect_domain() is not None:
        strength_of_other_records = redirect_strong_spf(spf)
    if not strength_of_other_records:
        strength_of_other_records = include_strong_spf(spf)

    return strength_of_other_records

#checks for ALL mechanism in the SPF. It should always go at the end of the SPF record.
def string_check_spf(spf):
    all_string_strength = True
    if spf.all_string is not None:
        if spf.all_string == "~all" or spf.all_string == "-all":
            all_string_strength = False
    else:
        all_string_strength = False

    if not all_string_strength:
        all_string_strength = redirect_include_check(spf)

    return all_string_strength

#prints out if SPF record is found or not. If found, then it tells if its strong or not!
def check_spf_strength(email_domain):
    strong_spf_record = True
    spf = spflib.SpfRecord.from_domain(email_domain)
    if spf is not None and spf.record is not None:
        all_string_strength = string_check_spf(spf_record)
        if all_string_strength is False:
            redirect = redirect_check_for_spf(spf_record)
            include = include_mec_check_for_spf(spf_record)
            spf_strong = False
            if redirect is True:
                spf_strong = True
            if include is True:
                spf_strong = True
    else:
        spf_strong = False

    return spf_strong

#printing out DMARC records
def retrieve_dmarc(email_domain):
    dmarc_record = dmarclib.DmarcRecord.from_domain(email_domain)
    if dmarc_record is not None and dmarc_record.record is not None:
        print(str(dmarc_record.record))
    return dmarc_record

#veifying the property of DMARC to be either None, Reject or Quarantine
def policy_check_dmarc(dmarc):
    check_strength_policy = False
    if dmarc.policy is not None:
        if dmarc.policy == "reject" or dmarc.policy == "quarantine":
            check_strength_policy = True
            
    return check_strength_policy

#retreiving the strength of dmarc record
def dmarc_strength(email_domain):
    strength_dmarc = False

    dmarc = retrieve_dmarc(email_domain)

    if dmarc is not None and dmarc.record is not None:
        strength_dmarc = policy_check_dmarc(dmarc)
    elif dmarc.get_org_domain() is not None:
        strength_dmarc = org_policy_check_for_dmarc(dmarc)

    return strength_dmarc

#checking if organisational DMARC policy exists or not. 
def org_policy_check_for_dmarc(record):
    policy_strength = False
    org = record.get_org_record()
    checks["org_record"] = str(org.record)
    if org.subdomain_policy is not None:
        if org.subdomain_policy == "quarantine" or org.subdomain_policy == "reject":
            policy_strength = True
        else:
            policy_strength = policy_check_dmarc(org)

    return policy_strength

for e in email_headers.items():

	# message id 
	if e[0].lower()=="message_id":
		checks["message_id"]=e[1]
	#retrieveing domain from the email	
	if e[0].lower()=="from":
		checks["sender"]=e[1]
		separator_1 = '@'
		result_1 = checks["sender"].split(separator_1, 1)[1]
		checks["sender"] = '@'+result_1.split('>',1)[0]

	# mail sent by the mail server
	if e[0].lower()=="received":
		checks["sender_client"]=e[1]

	# mail server detecting authentication
	if e[0].lower()=="authentication-results":
        # dkim check
		if(re.search("dkim=pass",e[1])):
			checks["dkim_record"]=True
		# spf check
		if(re.search("spf=pass",e[1])):
			checks["spf_record"]=True;
        #ip address check
		if(re.search("(\d{1,3}\.){3}\d{1,3}", e[1])):
			ip=re.search("(\d{1,3}\.){3}\d{1,3}", e[1])
			checks["ip_address"]=str(ip.group())
    # date and time check
	if e[0].lower()=="date":
		checks["date_time"]=e[1]
    # content type check
	if e[0].lower()=="content-type":
		checks["content_type"]=e[1]
    # subject check
	if e[0].lower()=="subject":
		checks["subject"]=e[1]

# main method 
if __name__ == "__main__":
    check_for_spoof = False
    email_domain = checks["sender"]
    checks["dmarc_record"] = dmarc_strength(email_domain)
    if (checks["dmarc_record"] is True and checks["spf_record"] is True):
       check_for_spoof = False

    else:
       check_for_spoof = True
       
print(Fore.BLUE+"\nInformation about the Email : ")
print(Fore.BLUE+"------------------------------ \n")
print(Fore.BLACK+"Message ID : "+checks["message_id"])
#printing spf record
if(checks["spf_record"]):
	print(Fore.BLACK+"SPF Record : PASS")
else:
	print(Fore.BLACK+"SPF Record : FAIL")
#printing dkim record
if(checks["dkim_record"]):
	print(Fore.BLACK+"DKIM Record : PASS")
else:
	print(Fore.BLACK+"DKIM Record : FAIL")
#printing dmarc record
if(checks["dmarc_record"]):
	print(Fore.BLACK+"DMARC Record : PASS")
	#rua specifies the URI of the mailbox to receive DMARC aggregate reports. It's required to request for DMARC aggregate reports.
	print(checks["org_record"])
else:
	print(Fore.BLACK+"DMARC Record : FAIL")
#printing ip address 
print(Fore.BLACK+"IP Address :  "+checks["ip_address"])
#printing date and time 
print(Fore.BLACK+"Date & Time : "+checks["date_time"])
#printing subject 
print(Fore.BLACK+"Subject : "+checks["subject"]+"\n\n")

print(Fore.MAGENTA+"OUTPUT : ")
print(Fore.MAGENTA+"-------------")
# check for domain spoofable or not
if check_for_spoof:
    print(Fore.RED+"Spoofing possible for " + email_domain)
else:
    print(Fore.GREEN+"Spoofing not possible for " + email_domain)
# check for email legitmate or not      
if((not checks["dkim_record"]) or (not checks["dmarc_record"]) or (not checks["spf_record"])):
	print(Fore.RED+"Spoofed Email Received")

else:
	print(Fore.GREEN+"Authentic Email Received")

print(Fore.BLUE+"\nAdditional Information about the Email :")
print(Fore.BLUE+"------------------------------------------ \n")
print(Fore.BLACK+"Mail : "+checks["sender"])
print(Fore.BLACK+"Provider : "+checks["sender_client"])
print(Fore.BLACK+"Content-Type : "+checks["content_type"])

