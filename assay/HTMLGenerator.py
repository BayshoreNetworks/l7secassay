"""
    Generator class to build the HTML content for storage
    in the output file
    
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
import vars
from libs import HTML
from libs.BeautifulSoup import BeautifulSoup as bs

genGraphs = vars.getGenerateGraphs
if genGraphs():
    from libs import graphs

class HTMLGenerator():
    HTML_OPEN = "<html>"
    HTML_CLOSE = "</html>"
    HTML_BODY_OPEN = "<body>"
    HTML_BODY_CLOSE = "</body>"
    HTML_HEAD_OPEN = "<head>"
    HTML_HEAD_CLOSE = "</head>"
    HTML_TITLE_OPEN = "<title>"
    HTML_TITLE_CLOSE = "</title>"
    
    def __init__(self, targeturl=""):
        self.targeturl = targeturl
        
        self.text1 = "Scan Results for "
        self.html = ""
        self.html += self.HTML_OPEN
        self.html += self.HTML_HEAD_OPEN
        self.html += self.HTML_TITLE_OPEN
        self.html += self.HTML_TITLE_CLOSE
        self.html += "<link rel=\"stylesheet\" type=\"text/css\" href=\"css/bayshore_style.css\" />"
        self.html += self.HTML_HEAD_CLOSE
        self.html += self.HTML_BODY_OPEN
        self.html += "<h1 class=\"logo\"><a href='#'><img src='logo.png' alt='Image' /></a></h1>"
        self.html += "<p>%s%s</p>" % (self.text1, targeturl)
        self.t = HTML.Table(header_row=['Status', 'Category', 'Attack Vector', 'Target'],
                            attribs={'class':'formtable'})
        
    def writeHtmlTableCell(self, success=False, attackType="", target="", vect=""):
        if success:
            _category = HTML.TableCell("<div style=\"white-space:normal;\">" + attackType + "</div>",
                                       attribs={'class':'cell_attack_success'})
            _target = HTML.TableCell(target, attribs={'class':'cell_attack_success'})
            _status = HTML.TableCell("Success", attribs={'class':'cell_attack_success'})
            _vector = HTML.TableCell("<div style=\"word-break:break-all;\">" + vect + "</div>", attribs={'class':'cell_attack_success'})
        else:
            _category = HTML.TableCell("<div style=\"white-space:normal;\">" + attackType + "</div>",
                                       attribs={'class':'cell_attack_failed'})
            _target = HTML.TableCell(target, attribs={'class':'cell_attack_failed'})
            _status = HTML.TableCell("Failed", attribs={'class':'cell_attack_failed'})
            _vector = HTML.TableCell("<div style=\"word-break:break-all;\">" + vect + "</div>", attribs={'class':'cell_attack_failed'})
            
        self.t.rows.append([_status, _category, _vector, _target])
        
    def generateHtmlStats(self, keyval={}):
        sts = "<p>Stats</p>"
        t = HTML.Table(header_row=['Type', 'Sent', 'Successful', 'Failed'],
                       attribs={'class':'formtable'})
        for key, value in sorted(keyval.iteritems(), key=lambda (k,v): (v,k)):
            if value[0] > 0:
                try:
                    atype = vars.typedesc[key][0]
                except KeyError:
                    atype = key.title()
                if value[1] < 1:
                    _category = HTML.TableCell(atype,
                                               attribs={"style":"word-break:break-all",
                                                        'class':'cell_attack_failed'})                      
                    _sent = HTML.TableCell(value[0], attribs={'class':'cell_attack_failed'})
                    _success = HTML.TableCell(value[1], attribs={'class':'cell_attack_failed'})
                    _fail = HTML.TableCell(value[2], attribs={'class':'cell_attack_failed'})
                else:
                    _category = HTML.TableCell(atype,
                                               attribs={"style":"word-break:break-all",
                                                        'class':'cell_attack_success'})
                    _sent = HTML.TableCell(value[0], attribs={'class':'cell_attack_success'})
                    _success = HTML.TableCell(value[1], attribs={'class':'cell_attack_success'})
                    _fail = HTML.TableCell(value[2], attribs={'class':'cell_attack_success'})
                
                t.rows.append([_category, _sent, _success, _fail])
        return sts + str(t)
    
    def genGraphs(self, keyval={}):
        thestr = ""
        cnt = 0
        for key, value in sorted(keyval.iteritems(), key=lambda (k,v): (v,k)):
            graph = graphs.BarGraph('hBar')
            sarr = []
            
            try:
                atype = vars.typedesc[key][0]
            except KeyError:
                atype = key.title()
            
            thestr += "<table border=\"1\" cellspacing=\"0\" cellpadding=\"0\"><tr><td><p>%s - Sent: %s</p></td></tr><tr><td>" % (atype, value[0])
            sarr.append(atype)
            #thestr += "var s%s = [%s, %s, %s];" % (cnt, value[0], value[1], value[2])
            graph.values.append((value[1], value[2]))
        
            graph.labels = sarr
            if cnt == 0:
                graph.legend = ['Succeeded', 'Failed']
            #graph.labelSpace = 10
            thestr += graph.create()
            thestr += "</td></tr></table>"
            cnt += 1
        return thestr
    
    def saveHTML(self, fhandle="", keyval={}):
        fhandle = fhandle
        f = open(fhandle, 'w')
        
        self.html += str(self.t)
        self.html += self.generateHtmlStats(keyval=keyval)
        
        if genGraphs():
            self.html += "<div><pre>"
            self.html += self.genGraphs(keyval=keyval)
            self.html += "</pre></div>"
        self.html += "<br />"
        self.html += self.HTML_BODY_CLOSE
        self.html += self.HTML_CLOSE
        
        # make it purty :-)
        soup = bs(self.html.encode('utf-8'), indentWidth='    ')
        prettyHTML = soup.prettify()
        f.write(prettyHTML)
        f.close()
          
