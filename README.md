assay
=====

Software to give users the ability to test the effectiveness of their WAF/Layer 7/Web Application Security solution(s).

Be forewarned:

Use and/or clone at your own risk:

*****************************************************************************************
**** WARNING: Contains live Malware … it is the only way to properly test these features
*****************************************************************************************
*****************************************************************************************
*****************************************************************************************

The purpose of this software is to give users the ability to test the effectiveness of their WAF solution(s).

********************************************************************************************************************
**** WARNING: Malware may make it up to your web server via assay ****

**** !!!!! DO NOT forget to look for and clean those files up !!!!! ****

**** PELIGRO: if you forget to clean those files up you may have a gaping hole in your infrastructure. ****

**** ACHTUNG: best practice: put DVWA on a VM ****

**** ACHTUNG: best practice: isolate this instance of DVWA from critical resources on your network. ****

**** CONSCIA: best practice: always clean up any testing Malware/Backdoor files from your test web server ****
********************************************************************************************************************

**** It is HIGHLY recommended that you DO NOT deploy this in a production environment. ****

**** It is HIGHLY recommended that you use an isolated part of your network for this type of testing. ****

Use Case/Scenario:

The version of DVWA included is set to its lowest security setting. So it represents a very insecure web application.
This type of app might not be updated in terms of security for a multitude of reasons (no budget, lack of knowledge, lack of time, etc).
So you purchase or build a WAF solution and route your traffic through it in order to protect this insecure web app.
Assay lets you test the effectiveness of your WAF because it already knows how to exploit DVWA. Hence, if your WAF is effective it will block assay's attacks.

Usage Diagram (I will slap a nicer one together over time):

 --------------                 --------------                 -------------- 
 |            |                 |            |                 |            |
 |            |                 |            |                 |            |
 |   assay    | --------------- |     WAF    | --------------- |    DVWA    |
 |            |                 |            |                 |            |
 |            |                 |            |                 |            |
 --------------                 --------------                 --------------

Requirements:

- Tor executable if you want to use the anonymize function


Steps:

1.	Set up the version of DVWA provided. 

	There are some small changes and additions to the Vanilla DVWA, for instance we force the lowest security setting.
	As per the documentation included with DVWA:
	
	Default username = 'admin'
	Default password = 'password'
	
	Simply copy the DVWA files from our Git repo to your Web Server (VM, metal, whatever).
	This doc does not cover web hosting so we assume you know how to create a virtual host and such.
	
	Setup the DB credentials by modifying '/config/config.inc.php'

	The variables are set to the following by default:

		$_DVWA[ 'db_user' ] = 'root';

		$_DVWA[ 'db_password' ] = '';

		$_DVWA[ 'db_database' ] = 'dvwa';
		
	Modify those values according to your environment.

	Using your browser then hit index.php from your virtual host (something like this):
	
	http://your.web.server/dvwa/index.php

	Database Setup
	To set up the database, simply click on the Setup button in the main menu.
	Then click on the 'Create / Reset Database' button.
	This will create / reset the database for you with some data in it.

	If you receive an error while trying to create your database, make sure your database credentials are correct within /config/config.inc.php

	For the shellshock test to function, you must enable cgi on Apache and copy the file to the cgi directory on your system:

 	For example, on Ubuntu 14.04:

		a2enmod cgid
		service apache2 reload
		cp ./l7assay/dvwa/vulnerabilities/shellshock/shellshock.cgi /usr/lib/cgi-bin/
		chmod +x  /usr/lib/cgi-bin/shellshock.cgi


2. 	Test connectivity

	Via browser you should be able to hit your instance of the DVWA app and log in using the default creds from step 1.
	Assuming connectivity is good to go move on to step 3.
	
3.	See usage statement:

		python assay.py -h
		usage: assay.py [-h] -s SECURE

		Bayshore Networks - assay

		optional arguments:
		-h, --help            	show this help message and exit
		-s SECURE, --secure SECURE
                        		level of security in front of DVWA instance (WAF present or not)
		-a 1, --anonymize 1   enables the use of tor

	Examples:

		To run thru a WAF using no SOCKS proxy:

		python assay.py -s1


		To run thru a WAF using a SOCKS proxy:

		python assay.py -s1 -a1


		To run directly against DVWA using no SOCKS proxy:

		python assay.py -s0


		To run directly against DVWA using a SOCKS proxy:

		python assay.py -s0 -a1

                        		
4.	Update vars.py by modifying the relevant variables to match your environment:

		targetproto = "http"
		targetfqdn = "your.site.tld"
		targetport = 80
		dvwa_server_path = "/opt/lampp/htdocs/hackable/uploads/"

5.	If you are going to use the anonymize option then you must make sure the tor executable exists on the system you are using to run assay

6.	Program run without a WAF in place

	Do a run of assay to make sure all is working and you get the baseline of hitting this vulnerable application from within your environment.
	This will yield a report in HTML called 'pre_waf_datetime.html'
	datetime is a date/time stamp so an example of a filename is: pre_waf_2012.10.23.20.18.35.html
	
	An example run statement for this step is:
	
		python assay.py -s0 -a1
	
7. 	Program run with a WAF in place

	Do a run of assay to test your WAF solution.
	This will yield a report in HTML called 'post_waf_datetime.html'
	datetime is a date/time stamp so an example of a filename is: post_waf_2012.10.23.20.18.35.html
	
	An example run statement for this step is:
	
		python assay.py -s1 -a1

********************************************************************************************************************
**** WARNING: Malware may make it up to your web server via assay ****

**** !!!!! DO NOT forget to look for and clean those files up !!!!! ****

**** PELIGRO: if you forget to clean those files up you may have a gaping hole in your infrastructure. ****

**** ACHTUNG: best practice: put DVWA on a VM ****

**** ACHTUNG: best practice: isolate this instance of DVWA from critical resources on your network. ****

**** CONSCIA: best practice: always clean up any testing Malware/Backdoor files from your test web server ****
********************************************************************************************************************





