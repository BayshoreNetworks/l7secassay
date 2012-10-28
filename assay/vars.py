"""
    Just a bunch of variables used by assay
    
    License:
    assay
    Copyright (C) 2010 - 2012 Bayshore Networks, Inc.

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
# vars
##################################################################
targetproto = "http"
targetfqdn = "your.site.tld"
targetport = 80
yourdomain = "yourdomain.tld"
exturl = "http://external.%s/" % yourdomain
extpath = "e4589efff654d91e26b43333dbf41425/"
apppath = ""
loginpage = "login.php"
loginbypass = "login2.php"
slash = "/"
targetpath = "vulnerabilities%s" % slash
malwarepath = "malware%s" % slash
staticpath = "static%s" % slash
htmlpath = "html%s" % slash
htmlfilename = "waf_"
htmlfileext = ".html"
user = "admin"
userpass = "password"
generateGraphs = False
useBrowser = True
successfulVectors = 0
blockedVectors = 0
redirtoken = "aHR0cDovL2V4dGVybmFsLmJheXNob3JlbmV0d29ya3MuY29tL2U0NTg5ZWZmZjY1NGQ5MWUyNmI0MzMzM2RiZjQxNDI1L3lvdXNob3VsZG5vdGJlaGVyZS5waHA="
##################################################################
typedesc = {
            #'brute':["Brute-Force Attack", " vectors", "OWASP Top 10 - A3: Broken Authentication and Session Management", 0],
            #'exposesession':["Information Leakage of Session ID", " data", "OWASP Top 10 - A3: Broken Authentication and Session Management", 1],
            #'redir':["Unvalidated Redirect Attack", "", "A10: Unvalidated Redirects and Forwards", 2],
            
            'exec':["Command Execution Attack", " vectors", "OWASP Top 10 - A1: Injection", 0],
            'fi':["File Inclusion Attack", " vectors", "OWASP Top 10 - A4: Insecure Direct Object References", 1],
            'xss_r':["Cross-Site Scripting (XSS) Reflective Attack", " vectors", "OWASP Top 10 - A2: Cross-Site Scripting (XSS)", 2],
            'xss_s':["Cross-Site Scripting (XSS) Stored Attack", " vectors", "OWASP Top 10 - A2: Cross-Site Scripting (XSS)", 3],
            'sqli':["SQL Injection Attack", " vectors", "OWASP Top 10 - A1: Injection", 4],
            'sqli_blind':["Blind SQL Injection Attack", "", "OWASP Top 10 - A1: Injection", 5],
            'upload':["File Upload Attacks", "", ["OWASP Top 10 - A1: Injection","OWASP Top 10 - A8: Failure to Restrict URL Access"], 6],
            
            #'csrf':["Cross-Site Request Forgery", " Attack", "OWASP Top 10 - A5: Cross-Site Request Forgery (CSRF)", 10],
            }

"""
    the value structure here is:
    
    [attackCount, attackSucceeded, attackFailed]
"""
typecount = {
            #'brute':[0,0,0],
            #'exposesession':[0,0,0],
            #'redir':[0,0,0],
            'exec':[0,0,0],
            #'csrf':[0,0,0],
            'fi':[0,0,0],
            'xss_r':[0,0,0],
            'xss_s':[0,0,0],
            'sqli':[0,0,0],
            'sqli_blind':[0,0,0],
            'upload':[0,0,0]
            }

def getMalwarePath():
    return malwarepath

def getStaticPath():
    return staticpath

def getUrl():
    targ = targetproto + "://" + targetfqdn
    if targetport != 80:
        targ += ":" + str(targetport)
    targ += "/"
    return targ

def getApppath():
    return apppath

def getHtmlPath():
    return htmlpath
    
def getHtmlFileName():
    return htmlfilename

def getHtmlFileExt():
    return htmlfileext

def getGenerateGraphs():
    return generateGraphs

def getUseBrowser():
    return useBrowser
