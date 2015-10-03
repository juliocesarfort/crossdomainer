#!/usr/bin/python
import urllib2
import sys
import argparse
import sqlite3
from xml.etree import ElementTree
import socket
import httplib

VERBOSE = False
DEFAULTTIMEOUT = 10
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
db = ''

def main():
    global VERBOSE
    socket.setdefaulttimeout(DEFAULTTIMEOUT)

    argparser = argparse.ArgumentParser(description='crossdomainer.py - cross domain policy inspector')
    argparser.add_argument('urllist', help='list with URLs to verify crossdomain policies')
    argparser.add_argument('-p', '--policy', help='verify Flash crossdomain.xml (default) or Silverlight')
    argparser.add_argument('-v', '--verbose', action='store_true', help='toggle verbose mode')
    args = argparser.parse_args()

    if args.verbose:
        VERBOSE = True

    url_list = args.urllist
    create_database('crossdomain-alexatop10000.db')

    #if 'flash' not in args.policy or 'silverlight' not in args.policy:
    #    print "Please select either Flash or Silverlight"
    #    sys.exit(0)

    fetch_crossdomain(url_list, 'flash')


def fetch_crossdomain(url_list, policy):
    try:
        fd = open(url_list, "r")
    except IOError as err:
        print "Error opening URL list: " + str(err)
        sys.exit(0)

    urls = fd.read().splitlines()

    if 'flash' in policy:
        crossdomainfile = '/crossdomain.xml'
    else:
        crossdomainfile = '/silverlight.xml'
        

    for url in urls:
        if not url.startswith("http"):
            url = "http://" + url

        url = url + crossdomainfile
        header_ua = {'User-Agent' : user_agent}
        req = urllib2.Request(url, headers=header_ua)

        try:
            response = urllib2.urlopen(req)
            crossdomain_file = response.read()

            if VERBOSE:
                print "Filename " + parse_filename(url)
                print "Crossdomain: " + crossdomain_file
                print ""

            crossdomain_filename = save_crossdomain(parse_filename(url), crossdomain_file)
            
            if 'flash' in policy:
                ret, notes = analyze_flashcrossdomain(url, crossdomain_filename)
                if ret != "Error":
                    insert_into_database(url, 'true', 'false', ret, notes)
            else:
                ret, notes = analyze_silverlightcrossdomain(url, crossdomain_filename)
                insert_into_database(url, 'false', 'true', ret, notes)

        except urllib2.HTTPError as err:
            if VERBOSE:
                print "[verbose] Error code: " + str(err.code)
                print "[verbose] Response: " + err.read()
        except urllib2.URLError as err:
            if VERBOSE:
                print "[verbose] URL %s seems to be down: %s" % (url, str(err.reason))
        except httplib.BadStatusLine as err:
            if VERBOSE:
                print "[verbose] httplib error: " + str(err)
            pass
        except socket.error as err:
            if VERBOSE:
                print "[verbose] Socket error: " + str(err)
            pass
        except socket.timeout as err:
            if VERBOSE:
                print "[verbose] Socket timeout: " + str(err)
            pass


def analyze_flashcrossdomain(url, filename):
    try:
        xmldocument = ElementTree.parse(filename)
    except Exception as err:
        print "Error parsing XML: " + str(err)
        return ("Error", "Parsing error")

    # default values for rate and notes
    rate = "NOTFOUND"
    notes = "No allow-access-from found in the crossdomain file."

    for domain in xmldocument.findall('allow-access-from'):
        print domain.attrib['domain']
        d = domain.attrib['domain']

        # checks for the most insecure form of crossdomain
        # if found, we return immediately - no need to check for anything else
        if d == '*':
            rate = "Insecure"
            notes = "Very insecure crossdomain policy"
            if VERBOSE:
                print notes
            return (rate, notes)
        
        # --- TODO: rethink this entire algorithm. the idea is on its way but in
        # some cases it will not work as it should ---

        # checks for an insecure crossdomain where it is *.domain but
        # domain is not part of the URL, so not controlled by the assessed domain
        idx = d.find('*.')
        if idx != -1:
            if d[:idx] in url:
                rate = "Secure"
                notes = "Secure crossdomain policy"
                if VERBOSE:
                    print notes
            else:
                rate = "Moderate"
                notes = "Partially insecure crossdomain policy - " + d
                if VERBOSE:
                    print notes
        else:
            if url not in d:
                rate = "Moderate"
                notes = "Partially insecure crossdomain policy - " + d
                if VERBOSE:
                    print notes
            else:
                rate = "Secure"
                notes = "Secure crossdomain policy"
                if VERBOSE:
                    print notes

    return (rate, notes)


def analyze_silverlightcrossdomain(filename):
    print "Silverlight crossdomain analysis not yet implemented."
    sys.exit(0)


def save_crossdomain(filename, content):
    try:
        fd = open(filename, "w")
    except IOError as err:
        print "Error writing to file %s: %s" % (filename, err)

    fd.write(content)
    fd.close()
    return filename


def parse_filename(url):
        return url.replace(":", "_").replace("/","_")

def create_database(dbname):
    global db
    
    try:
        db = sqlite3.connect(dbname)
    except Exception as err:
        print "Error creating database: " + str(err)
        sys.exit(0)

    cursor = db.cursor()
    if VERBOSE:
        print "[verbose] Flushing all database tables"
    try:
        cursor.execute('''SELECT * FROM crossdomain''')
    except sqlite3.OperationalError as err:
        if VERBOSE:
            print "[verbose] Table 'crossdomain' not found. Does the database even exist?"
    #finally:
    #    cursor.execute('''DROP TABLE crossdomain''')

    if VERBOSE:
        print "[verbose] Creating 'crossdomain' table"
    try:
        cursor.execute('''CREATE TABLE crossdomain(id INTEGER PRIMARY KEY, url TEXT unique, flash TEXT, silverlight TEXT, rate TEXT, notes TEXT)''')
    except sqlite3.OperationalError as err:
        if VERBOSE:
            print "[verbose] Table 'crossdomain' already exists. Skipping."
        pass
    
    db.commit()
    return


def insert_into_database(url, flash, silverlight, rate, notes):
    global db

    try:
        cursor = db.cursor()
    except Exception as err:
        print "Error acquiring a cursor to the database: " + str(err)
        sys.exit(0)

    try:
        cursor.execute('''INSERT INTO crossdomain(url, flash, silverlight, rate, notes) VALUES(?,?,?,?,?)''', (url, flash, silverlight, rate, notes))
    except sqlite3.IntegrityError as err:
        if VERBOSE:
            print "The URL %s has already been inserted into the database and analyzed. Skipping." % url
        pass

    db.commit()
    return


if __name__ == '__main__':
    main()
