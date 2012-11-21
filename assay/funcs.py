"""
    Just a bunch of useful and often used functions for assay
    
    License:
    assay
    Copyright (C) 2010 - 2013 Bayshore Networks, Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import sys
import mechanize
import random
import re
import socket
import urllib2
import time
import vars
from libs.BeautifulSoup import BeautifulSoup as bs
from libs import HTML
from datetime import datetime
from string import letters
from string import digits
from random import choice
from random import randint

stepOne = 5
stepTwo = 9
stepThree = 13
stepFour = 17
stepFive = 21
stepSix = 25

def createRandAlpha(length=0):
    ''' create random alpha strings '''
    return ''.join(choice(letters) for x in xrange(length or randint(10, 30)))

"""
    Simply prints out an opening banner for the prog
"""
def printBanner(loginpage, user):
    attackOutPut(stepOne, "info", "Bayshore Networks, Inc. - assay [DVWA Web App Attack]")
    attackOutPut(stepOne, "info", "-------------------------------------")
    attackOutPut(stepOne, "info", "Target: %s" % loginpage)
    attackOutPut(stepOne, "info", "Target User: %s" % user)
    print
# EOF

"""
    Performs the login function against the target DVWA app.
    It either succeeds and returns a handle to the Browser object
    or it shuts the prog down. This handle, if returned, is the
    handle used by the whole prog so as to leverage one session.
"""
def doLogin(targetloginpage):

    # compile regex for successful auth
    regAuth = re.compile("Welcome",re.I+re.MULTILINE)

    # gather login form info
    credresp = doLoginFormDiscovery(targetloginpage)
    ##################################################################
    # login to the app via a POST form submit
    fp = mechanize.Browser()
    # ignore robots
    fp.set_handle_robots(False)
    uaheader = getRandUserAgent()
    attackOutPut(stepOne, "info", "Using randomly chosen User-agent: \"%s\"" % uaheader)

    fp.addheaders = [('User-agent', uaheader)]
    fp.open(targetloginpage)
    fp.select_form(nr=0)
    # view forms if necessary
    #for form in fp.forms():
    #    print form
    fp[credresp['user']] = vars.user
    fp[credresp['passwd']] = vars.userpass
    if 'hiddenfields' in credresp:
        for k, v in credresp['hidden'].items():
            fp.find_control(k).readonly = False
            fp[k] = v
    # submit form and deal with the response below
    fp.submit()
    # test for successful auth, if good return Browser obj
    if regAuth.search(str(fp.response().read())):
        attackOutPut(stepOne, "discovered", "Authentication is successful, inside the app, let's play :-]\n")
        return fp
    else:
        attackOutPut(stepOne, "nothingfound", "Authentication is NOT successful, exiting :-[\n")
        sys.exit()
# EOF

"""
    Attempts to dynamically detect form elements from a
    login form. So if there is no PasswordControl present
    it isnt a login form and None gets returned.
"""
def getLoginFormVals(val):
    #print val
    d = {}
    dd = {}
    # this regex should detect the textcontrol (hopefully username)
    # and passwordcontrol fields of the form to be attacked
    reg = re.compile(r"<(\w*Control)\((\w*)=[\)(\w:\/.)]*[\>\s]", re.MULTILINE)
    matches = [m.groups() for m in reg.finditer(val)]
    for m in matches:
        #print m
        if m[0] == "TextControl":
            d['TextControl'] = m[1]
        if m[0] == "PasswordControl":
            d['PasswordControl'] = m[1]
    # this regex should detect any hidden html fields in the target form
    hiddenreg = re.compile(r"<(HiddenControl)\((\w*)=([\w:\/.]*)", re.MULTILINE)
    matches = [m.groups() for m in hiddenreg.finditer(val)]
    for m in matches:
        dd[m[1]] = m[2]
    # if any hidden fields were detected then
    # populate dictionary d with dd
    if dd:
        d['HiddenControl'] = dd
    # only return the dict if both a textcontrol (for username)
    # and password control has been discovered
    if d:
        if 'PasswordControl' in d and 'TextControl' in d:
            return d
    else:
        return None
# EOF

"""
    Attempts to dynamically detect login form from a page.
"""
def doLoginFormDiscovery(target):
    attackOutPut(stepThree, "step", "Attempting to detect Login form values")
    detectedforms = []
    # simple ones
    """
        the next 2 values need to get appropriate strings
        relevant to the target form, we will auto-detect
        them based on the value from the -l switch
        if you don't know what that means you shouldn't be
        running this prog :-)
    """
    formusernamefield = ''
    formpasswordfield = ''
    hiddenfields = False
    # let's make an attempt at intelligently
    # detecting the form field names
    try:
        nfp = mechanize.Browser()
        # ignore robots
        nfp.set_handle_robots(False)
        nfp.open(target)

        # iterate over the forms on the target page
        for form in nfp.forms():
            ff = getLoginFormVals(str(form))
            # if getLoginFormVals returns something
            # other than None
            if ff:
                detectedforms.append(ff)
        nfp.close()
    except(socket.gaierror, urllib2.HTTPError), msg:
        attackOutPut(stepFour, "info", msg)
        sys.exit(1)

    # process form data
    if len(detectedforms) < 1:
        attackOutPut(stepFour, "nothingfound", "Sorry no forms detected for attacking")
        #sys.exit(0)
    # optimal
    if len(detectedforms) == 1:
        attackOutPut(stepFour, "discovered", "One form detected, using it ...")
        #print detectedforms
        attackOutPut(stepFive, "discovered", "Username field: %s" % detectedforms[0]['TextControl'])
        formusernamefield = detectedforms[0]['TextControl']
        attackOutPut(stepFive, "discovered", "Password field: %s" % detectedforms[0]['PasswordControl'])
        formpasswordfield = detectedforms[0]['PasswordControl']
        if 'HiddenControl' in detectedforms[0]:
            hiddenfields = True
            attackOutPut(stepFive, "discovered", "Hidden Fields detected:")
            for k, v in detectedforms[0]['HiddenControl'].items():
                attackOutPut(stepSix, "discovered", "%s = %s" % (k, v))
        print
        #sys.exit(0)
    if len(detectedforms) > 1:
        attackOutPut(stepFour, "discovered", "More than one form detected, exiting")
        sys.exit(0)

    if hiddenfields:
        return {'user':formusernamefield, 'passwd':formpasswordfield, 'hidden':detectedforms[0]['HiddenControl']}
    else:
        return {'user':formusernamefield, 'passwd':formpasswordfield}
    #######################################################################
# EOF

"""
    Returns a randomly chosen value to be used as the User-Agent
"""
def getRandUserAgent():
    # pool of User-Agent headers to choose from
    headers = ['Googlebot/2.1 (http://www.googlebot.com/bot.html)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 6.0; MSN 2.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Win32)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; Arcor 5.005; .NET CLR 1.0.3705; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; YPC 3.0.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               "Mozilla/5.0 (compatible)",
               "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2",
               "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2)",
               "Mozilla/5.0 (compatible; Konqueror/2.2.2; Linux 2.4.14-xfs; X11; i686)",
               "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13",
               "Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3",
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.8) Gecko/20050511',
               'Mozilla/5.0 (X11; U; Linux i686; cs-CZ; rv:1.7.12) Gecko/20050929',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl-NL; rv:1.7.5) Gecko/20041202 Firefox/1.0',
               'Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.7.8) Gecko/20050609 Firefox/1.0.4',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.9) Gecko/20050711 Firefox/1.0.5',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.10) Gecko/20050716 Firefox/1.0.6',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8) Gecko/20051107 Firefox/1.5',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.8.0.4) Gecko/20060508 Firefox/1.5.0.4',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.6) Gecko/20060808 Fedora/1.5.0.6-2.fc5 Firefox/1.5.0.6 pango-text',
               'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.0.7) Gecko/20060909 Firefox/1.5.0.7',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20060601 Firefox/2.0 (Ubuntu-edgy)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070220 Firefox/2.0.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070221 SUSE/2.0.0.2-6.1 Firefox/2.0.0.2',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9a1) Gecko/20061204 GranParadiso/3.0a1',
               "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
               "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
               "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
               "Windows-RSS-Platform/1.0 (MSIE 7.0; Windows NT 5.1)",
               "Windows NT 6.0 (MSIE 7.0)",
               "Windows NT 4.0 (MSIE 5.0)",             
               "Opera/6.x (Windows NT 4.0; U) [de]",
               "Opera/7.x (Windows NT 5.1; U) [en]",
               'Opera/8.0 (X11; Linux i686; U; cs)',
               'Opera/8.51 (Windows NT 5.1; U; en)',
               'Opera/9.0 (Windows NT 5.1; U; en)',
               'Opera/9.01 (X11; Linux i686; U; en)',
               'Opera/9.02 (Windows NT 5.1; U; en)',
               'Opera/9.10 (Windows NT 5.1; U; en)',
               "Opera/9.20 (Windows NT 6.0; U; en)",
               'Opera/9.23 (Windows NT 5.1; U; ru)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50',
               'Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.50',
               "neuroFuzz testing (compatible)",
               "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)"
                ]
    return random.sample(headers, 1)[0]
# EOF

"""
    Attempts to dynamically detect any form from a page.
"""
def doFormDiscovery(fp, target):
    attackOutPut(stepThree, "step", "Attempting to detect form values")
    detectedforms = []
    # simple ones
    """
        the next 2 values need to get appropriate strings
        relevant to the target form, we will auto-detect
        them based on the value from the -l switch
        if you don't know what that means you shouldn't be
        running this prog :-)
    """
    # let's make an attempt at intelligently
    # detecting the form field names
    try:
        fp.open(target)

        # iterate over the forms on the target page
        for form in fp.forms():
            ff = getFormVals(str(form))
            # if getLoginFormVals returns something
            # other than None
            if ff:
                detectedforms.append(ff)
    except(socket.gaierror, urllib2.HTTPError, urllib2.URLError), msg:
        attackOutPut(stepFour, "info", msg)
        #sys.exit(1)
        

    if len(detectedforms) == 1:
        attackOutPut(stepFour, "discovered", "One form detected, using it ...")
        return detectedforms
    if len(detectedforms) < 1:
        attackOutPut(stepFour, "nothingfound", "No form detected")
        return None
# EOF

"""
    Attempts to dynamically detect form elements from a
    form. It probably needs some development to be full
    fledged in its approach. But for now it meets the
    need.
"""
def getFormVals(val):
    #print val
    d = {}
    dd = {}
    # this regex should detect the controls of the form to be attacked
    reg = re.compile(r"<(\w*Control)\((\w*)=[<\)(\w:\/.)]*[\>\s]", re.MULTILINE)
    matches = [m.groups() for m in reg.finditer(val)]
    for m in matches:
        #print m
        if m[0] == "TextControl":
            d['TextControl'] = m[1]
        if m[0] == "PasswordControl":
            d['PasswordControl'] = m[1]
        if m[0] == "FileControl":
            d['FileControl'] = m[1]
    # this regex should detect any hidden html fields in the target form
    hiddenreg = re.compile(r"<(HiddenControl)\((\w*)=([\w:\/.]*)", re.MULTILINE)
    matches = [m.groups() for m in hiddenreg.finditer(val)]
    for m in matches:
        dd[m[1]] = m[2]
    # if any hidden fields were detected then
    # populate dictionary d with dd
    if dd:
        d['HiddenControl'] = dd
    # only return the dict if both a textcontrol (for username)
    # and password control has been discovered
    if d:
        #if 'PasswordControl' in d and 'TextControl' in d:
        return d
    else:
        return None
# EOF

"""
    An implementation of the Levenshtein algorithm
    I found on the Internet.
"""
def levenshtein(a,b):
    "Calculates the Levenshtein distance between a and b."
    n, m = len(a), len(b)
    if n > m:
        # Make sure n <= m, to use O(min(n,m)) space
        a,b = b,a
        n,m = m,n

    current = range(n+1)
    for i in range(1,m+1):
        previous, current = current, [i]+[0]*n
        for j in range(1,n+1):
            add, delete = previous[j]+1, current[j-1]+1
            change = previous[j-1]
            if a[j-1] != b[i-1]:
                change = change + 1
            current[j] = min(add, delete, change)

    return current[n]
# EOF

"""
    Performs form submission via a mechanize Browser
    object that gets passed in.
"""
def formSubmit(fp, targetpage, formid, formelements, sleep=False):

    try:
        fp.open(targetpage)
        if type(formid) is int:
            fp.select_form(nr=formid)
        if type(formid) is str:
            fp.select_form(name=formid)
        # apply values to form elements
        for k,v in formelements.items():
            fp[k] = v

        # stagger a pause in the action and then
        if sleep:
            time.sleep(5 * random.random())
        # submit form and deal with the response below
        fp.submit()

        return str(fp.response().read())
    except Exception, e:
        if isBlock(e):
            pass
        else:
            return "Error in form submit: %s" % e

# EOF

"""
    The function that spits out data to the screen.
"""
def attackOutPut(n, status, s):
    #stats = ['[+]','[-]','[!]','[>]']
    stats = {
            "step":'[>]',
            "info":'[!]',
            "discovered":'[+]',
            "nothingfound":'[-]'
            }
    print " "*n + stats[status] + " " + str(s)
# EOF

"""
    sometimes a WAF does not redirect a malicious request to some
    specific page or site. it simply performs the response to the
    malicious request. we will look for the following values in
    the actual body of a response. the ones used here are from
    real detections in the field.
"""
def isBlock(resp):
    #print "Resp: %s" % resp
    blockDetect = ['Not Acceptable', 
                   '406', 
                   'Method Not Implemented', 
                   '501', 
                   'Error',
                   '500', 
                   'Internal Server Error', 
                   '400', 
                   'Bad Request']

    """
        return True if any of the blockDetect values are detected.
        this would mean we suspect a WAF blocked our malicious
        activity
    """
    for block in blockDetect:
        if block in resp:
            vars.blockedVectors += 1
            return True

    return False
# EOF

"""
    just output of some stats
"""
def printStats():
    print
    attackOutPut(stepTwo, "info", "Stats:")
    succCnt = 0
    for key, value in sorted(vars.typecount.iteritems(), key=lambda (k,v): (v,k)):
        if value[0] > 0:
            try:
                atype = vars.typedesc[key][0]
            except KeyError:
                atype = key.title()
            attackOutPut(stepThree, "info", "%s: Sent: %s, Successful: %s, Failed: %s" % (atype, value[0], value[1], value[2]))
            succCnt += value[1]
            
    #funcs.attackOutPut(funcs.stepTwo, "info", "%d injected vectors are suspected to be successful" % vars.successfulVectors)
    vect = "vectors are"
    if succCnt < 1:
        vect = "vector was"
    attackOutPut(stepTwo, "info", "%d injected %s suspected successful" % (succCnt,vect))
    vect = "vectors"
    if vars.blockedVectors < 1:
        vect = "vector was"    
    attackOutPut(stepTwo, "info", "%d injected %s suspected to have been blocked" % (vars.blockedVectors,vect))
    print
# EOF

"""
    just some output of results
"""
def printResults(successfulattacks=[], url=''):
    if len(successfulattacks) >= 1:
        attackOutPut(stepOne, "info", "The following attack vectors were successful against %s" % url)
        for k,v in successfulattacks.items():
            if type(vars.typedesc[k][2]) is str:
                outstr = "This application has failed tests covering %s, Category: %s" % (vars.typedesc[k][2], vars.typedesc[k][0])
            if type(vars.typedesc[k][2]) is list:
                outstr = "This application has failed tests covering "
                cnt = 1

                for s in vars.typedesc[k][2]:
                    if cnt == len(vars.typedesc[k][2]):
                        outstr += s
                    else:
                        outstr += s + ", and "
                    cnt += 1
                outstr += ", Category: %s" % vars.typedesc[k][0]

            attackOutPut(stepTwo, "discovered", outstr)
            for val in v:
                attackOutPut(stepThree, "discovered", "%s" % val)
    else:
        failed = """All attack vectors have FAILED,
        the current protective measures are 100% effective!"""
        attackOutPut(stepOne, "info", "%s" % failed)
# EOF

"""

"""
def checkArgs(value):
    value = int(value)
    if value >= 0 and value <= 1:
        return True
    return False
# EOF

def getTimeStamp():
    return '%s' % datetime.now().strftime('%Y.%m.%d.%H.%M.%S')

