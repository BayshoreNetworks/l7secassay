assay
=====

Software to give users the ability to test the effectiveness of their WAF/Layer 7/Web Application Security solution(s).

Please read assay/README

Be forewarned:

Use and/or clone at your own risk:

*****************************************************************************************
**** WARNING: Contains live Malware … it is the only way to properly test these features
*****************************************************************************************

For the shellshock test to function, you must enable cgi on Apache and copy the file to the cgi
directory on your system:

  For example, on Ubuntu 14.04:

    a2enmod cgid
    service apache2 reload
    cp ./l7assay/dvwa/vulnerabilities/shellshock.cgi /usr/lib/cgi-bin/
    chmod +x  /usr/lib/cgi-bin/shellshock.cgi
