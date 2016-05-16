"""
    Just a bunch of variables used by assay

    License:
    assay
    Copyright (C) 2010 - 2015 Bayshore Networks, Inc.

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
import base64

# vars you need to manage
##################################################################
# DVWA info
targetproto = "http"
targetfqdn = "your.site.tld"
targetport = 80
user = "admin"
userpass = "password"
dvwa_server_path = "/web/server/dvwa/hackable/uploads/"
'''
    HTTP status codes sent back by WAF when it
    blocks or performs a deny operation
'''
waf_response_codes = [500]

'''
    external host info - optional
'''
yourdomain = "yourdomain.tld"
exthost = "host"
exturl = "http://%s.%s/" % (exthost,yourdomain)
extpath = "e4589efff654d91e26b43333dbf41425/"
extresource = "youshouldnotbehere.php"

# output info
generateGraphs = True
useBrowser = False
##################################################################
# do not touch anything below this line
##################################################################
apppath = ""
loginpage = "login.php"
loginbypass = "login2.php"
slash = "/"
targetpath = "vulnerabilities%s" % slash
malwarepath = "malware%s" % slash
staticpath = "static%s" % slash
htmlpath = "html%s" % slash
hackableuploadpath = "hackable%suploads%s" % (slash, slash)
stored_exploitpath = "stored_exploits%s" % slash
backdoors_path = "%sbackdoor%s" % (stored_exploitpath, slash)
sqlinjection_path = "sql-injection%s" % slash
xss_path = "xss%s" % slash
htmlfilename = "waf_"
htmlfileext = ".html"
successfulVectors = 0
blockedVectors = 0
#redirtoken = "aHR0cDovL2V4dGVybmFsLmJheXNob3JlbmV0d29ya3MuY29tL2U0NTg5ZWZmZjY1NGQ5MWUyNmI0MzMzM2RiZjQxNDI1L3lvdXNob3VsZG5vdGJlaGVyZS5waHA="
redirtoken = base64.b64encode(exturl + extpath + extresource)

typedesc = {
            #'brute':["Brute-Force Attack", " vectors", "OWASP Top 10 - A3: Broken Authentication and Session Management", 0],
            #'redir':["Unvalidated Redirect Attack", "", "A10: Unvalidated Redirects and Forwards", 2],

            'exec':["Command Execution Attack", " vectors", "OWASP Top 10 - A1: Injection", 0],
            'fi':["File Inclusion Attack", " vectors", "OWASP Top 10 - A4: Insecure Direct Object References", 1],
            'xss_r':["Cross-Site Scripting (XSS) Reflective Attack", " vectors", "OWASP Top 10 - A2: Cross-Site Scripting (XSS)", 2],
            'xss_s':["Cross-Site Scripting (XSS) Stored Attack", " vectors", "OWASP Top 10 - A2: Cross-Site Scripting (XSS)", 3],
            'sqli':["SQL Injection Attack", " vectors", "OWASP Top 10 - A1: Injection", 4],
            'sqli_blind':["Blind SQL Injection Attack", "", "OWASP Top 10 - A1: Injection", 5],
            'upload':["File Upload (Ingress) Attacks", "", ["OWASP Top 10 - A1: Injection","OWASP Top 10 - A8: Failure to Restrict URL Access"], 6],
            #'exposesession':["Information Leakage of Session ID", " data", "OWASP Top 10 - A3: Broken Authentication and Session Management", 7],
            #'csrf':["Cross-Site Request Forgery", " Attack", "OWASP Top 10 - A5: Cross-Site Request Forgery (CSRF)", 10],
            'download':["File Download (Egress) Attacks", "", "Spreading File-based Malware via Egress", 7],
            'request_headers':["HTTP Request Header Attack", " vectors", "", 8],
            'backdoor_access':["HTTP BackDoor Access", "", "", 9],
            }

"""
    the value structure here is:

    [attackCount, attackSucceeded, attackFailed]
"""
typecount = {
            #'brute':[0,0,0],
            #'redir':[0,0,0],
            'exec':[0,0,0],
            #'csrf':[0,0,0],
            'fi':[0,0,0],
            'xss_r':[0,0,0],
            'xss_s':[0,0,0],
            'sqli':[0,0,0],
            'sqli_blind':[0,0,0],
            'upload':[0,0,0],
            'download':[0,0,0],
            #'exposesession':[0,0,0]
            'recon':[0,0,0],
            'request_headers':[0,0,0],
            'backdoor_access':[0,0,0]
            }

download_file_sigs = {'c99.bin':'74f1048753ed36a1de4f0d8b28dd78f5',
                      'ce014b08ae5d68a3eafd95807285e2cd':'ce014b08ae5d68a3eafd95807285e2cd',
                      'y3ym.exe':'5c0b7198187a971112a3e504c3ab9369'
                      }

backdoors_file_sigs = {'c99.php':['74f1048753ed36a1de4f0d8b28dd78f5','PHP Shell . Net'],
                       'r57.php':['7eae6bcb978d5cdecc34e146b22526aa','r57shell']
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

def getRedirToken():
    return redirtoken

def getExtUrl():
    return exturl + extpath

def getHackableUploadPath():
    return hackableuploadpath

def getBackdoorData():
    return (backdoors_path,backdoors_file_sigs)

def getSqlInjectionPath():
    return sqlinjection_path

def getXssPath():
    return xss_path
