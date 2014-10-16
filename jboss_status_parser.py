# jboss_status_parser.py - This script will parse the JBoss status page
#                          for IP addresses, domain names, and request
#                          information. This data is stored in a python
#                          dictionary and printed as parsed data for 
#                          easy reference.
# 
# Copyright (c) 2011, InGuardians, Inc. <consulting@inguardians.com>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Project Start Date:  July 23, 2013
# Point Of Contact:    Don C. Weber <don@inguardians.com>

import sys
import urllib2
import re
import time
from xml.dom import minidom

def usage():
    print "\n"
    print "Usage: %s [-h] [-D -DD -DDD] -t <target_list> [-c <number>] [-d <number>] [-p] [-f] [-q]" % sys.argv[0]
    print "   -h: print help"
    print "   -D: turn on debugging statements"
    print "   -DD: turn on verbose debugging statements"
    print "   -DDD: turn on very verbose debugging statements"
    print "   -t <target_list>: target list. Can be single target or comma separated list (no spaces). Targets can be domain names or IP addresses."
    print "   -c <number>: Number of minutes to run the query. Default is to run 1 minute."
    print "   -d <number>: Seconds of delay between query runs. Default is 2 seconds."
    print "   -f: Use full status. Defaults to normal output. FIXME: Full status is broken because of unclosed anchor tags (<a>)"
    print "   -p: Use HTTP protocol. Default is HTTPS"
    print "\n\n"
    sys.exit()
    
if len(sys.argv) == 1:
    usage()

STATUSES = ("/status","/status?full=true")  # Normal or Full Status report. FIXME: Full status is broken because of unclosed anchor tages (<a>)
PROTOS   = ('https://','http://')           # Protocol to use. Default to https:
THOSTS   = []                               # Target domain or IP Address
TURLS    = []                               # Combined Target URLs
COUNT    = 1                                # Number of minutes to run. Default is 1.
DELAY    = 2                                # Number of seconds delay between query runs. Default is 2 seconds
DEBUG    = False                            # Debugging. Default OFF
VDEBUG   = False                            # Verbose Debugging. Default OFF
VVDEBUG  = False                            # Very Verbose Debugging. Default OFF
QUIET    = False                            # Control the status messages. Default is to print status messages.

PROTO    = PROTOS[0]
STATUS   = STATUSES[0]
QUERIES  = {}

# Parse command line arguments
while len(sys.argv) > 1:
    op = sys.argv.pop(1)
    # Help
    if op == '-h':
        usage()
    # DEBUG
    if op == '-D':
        DEBUG = True
    # Verbose DEBUG
    if op == '-DD':
        VDEBUG = True
    # Very Verbose DEBUG
    if op == '-DDD':
        VVDEBUG = True
    # Targets
    if op == '-t':
        # Targets can be a single IP or Domain or a comma separated list of the same
        THOSTS = sys.argv.pop(1).split(',')
    # Count
    if op == '-c':
        # Number of times to run
        #TODO: make this a period of time
        COUNT = int(sys.argv.pop(1))
    # Delay
    if op == '-d':
        # Number of seconds to delay between query runs.
        DELAY = int(sys.argv.pop(1))
    # Use HTTP instead of HTTPS
    if op == '-p':
        PROTO = PROTO[1]
    # Grab full status
    if op == '-f':
        STATUS = STATUS[1]
    # Quiet mode
    if op == '-q':
        QUIET = True

# Test for targets or bail
if THOSTS:
    for e in THOSTS:
        TURLS.append(PROTO + e + STATUS)
else:
    usage()

# Regular Expressions for IP addresses and hostnames
# http://stackoverflow.com/questions/106179/regular-expression-to-match-hostname-or-ip-address
ValidIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
ValidHostnameRegex = "^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"
SlashEncoded = "%2F"

def print_data_dict(data_dict):
    # Sort and print the contents of the provided data dictionary

    print "\n\n"
    for ics in data_dict.keys():
        print "Internal Call Server:",ics,"at IP Address:",data_dict[ics][1]
        for qs in data_dict[ics][0].keys():
            print "    Query from client:",qs
            for ds in data_dict[ics][0][qs].keys():
                print "        with the following virtual domain names:",ds
                for ru in data_dict[ics][0][qs][ds]:
                    print "            for the following requests:",ru

    print "NOTE: the question marks (?) are normal and expected data."
    


def parse_data(data = None):
    # Parse data looking for the first IP address
    # Then skip ahead two for hostname and two more for rest of URI
    global QUERIES

    skip = 0
    for e in data:
        if not skip:
            # When we find a new server, start associating URIs with it
            if re.search(SlashEncoded,e.split('\t')[-1]):
                next_server = e.split('\t')[-1]
                if VDEBUG: print next_server
                proto,pserver = next_server.split(SlashEncoded)[0].split('-')
                sip,port = next_server.split(SlashEncoded)[1].split('-')
                #pserver = (proto,new_server,sip,port)
                new_server = proto + '://' + pserver + ':' + port
                if VDEBUG: print new_server
                #if pserver not in SERVERS:
                    #SERVERS.append(pserver)
                if new_server not in QUERIES.keys():
                    QUERIES[new_server] = [{},sip]
                continue

            # Grab/Store each IP address we see. These may or may not be associated with a server or URI.
            # Test for valid IP address.
            if re.match(ValidIpAddressRegex,e.split('\t')[-1]):
                new_ip = e.split('\t')[-1]
                if VDEBUG: print new_ip
                #if new_ip not in QUERIES.keys():
                    #QUERIES[new_ip] = {}
                if new_ip not in QUERIES.get(new_server)[0]:
                    QUERIES[new_server][0][new_ip] = {}
                skip = 1
        else:
            # Grab/Store URI. Most times this will just be a ?
            if skip == 6:
                new_uri = e.split('\t')[-1]
                if VDEBUG: print new_uri
                #if new_uri not in QUERIES[new_ip].get(new_host):
                    #QUERIES[new_ip][new_host].append(new_uri)
                if new_uri not in QUERIES[new_server][0][new_ip].get(new_host):
                    QUERIES[new_server][0][new_ip][new_host].append(new_uri)
                # Clean up for next server
                new_ip = new_host = new_uri = ''
                skip = 0
                continue
            # Grab/Store domain name. Most times this will just be a ?
            if skip == 3:
                new_host = e.split('\t')[-1]
                if VDEBUG: print new_host
                #if new_host not in QUERIES.get(new_ip):
                    #QUERIES[new_ip][new_host] = []
                if new_host not in QUERIES[new_server][0].get(new_ip):
                    QUERIES[new_server][0][new_ip][new_host] = []
            skip += 1

    # Print results
    if VDEBUG:
        print "================"
        print "QUERIES CONTENTS"
        print "================"
        print QUERIES
        print '\n\n'

    return QUERIES


if __name__ == "__main__":

    print "Starting JBoss Status Queries at ",time.asctime( time.localtime(time.time()) ) + "."
    print "Brought to you by InGuardians, Inc."
    ftime = time.time() + (COUNT * 60)
    while ftime > time.time():
        # Loop throught targets
        for e in TURLS:
            # Print status message
            if not QUIET: print "Processing:", e,"at",time.asctime( time.localtime(time.time()) )

            # Get data from status webpage
            try:
                data = urllib2.urlopen(e).read()
            except:
                try:
                    # Processing all day may run into problems. Use "try" to attempt to print data before fail
                    # Print Parsed Data
                    print "Grabbing URL Failed. Check usage.\n"
                    print results
                except:
                    print "Could not print results.\n"
                    print "\nJBoss Status Queries failed at ",time.asctime( time.localtime(time.time()) ) + ".\n"
                    pass
                sys.exit()
            
            # Verbose VDEBUGing because this will output a LOT of data. Use wisely.
            if VVDEBUG: print
            if VVDEBUG: print repr(data)
            if VVDEBUG: print

            # Replace automatically changes things that mess up our data
            # Make pretty adds the newline character so that we can split out lines
            # Tags that are not closed WILL cause parsing to fail
            try:
                data = minidom.parseString(data.replace('<br>','<br />').replace(' nowrap','')).toprettyxml().split('\n')
            except:
                # Processing all day may run into problems. Use "try" to attempt to print data before fail
                # NOTE: This could cause problems for debugging what is failing to parse. Therefore, remove if necessary
                try:
                    # Print Parsed Data
                    print "Parsing input from status page failed\n"
                    print results
                except:
                    print "Could not print results.\n"
                    print "\nJBoss Status Queries failed at ",time.asctime( time.localtime(time.time()) ) + ".\n"
                    pass
                sys.exit()

            # Parse Data
            try:
                results = parse_data(data)
            except:
                try:
                    # Processing all day may run into problems. Use "try" to attempt to print data before fail
                    # Print Parsed Data
                    print "Processing data input failed\n"
                    print results
                except:
                    print "Could not print results.\n"
                    print "\nJBoss Status Queries failed at ",time.asctime( time.localtime(time.time()) ) + ".\n"
                    pass
                sys.exit()

            # Print Parsed Data
            if DEBUG: print results

        # Get ready for next loop
        time.sleep(DELAY)
        

    # Print Parsed Data
    print_data_dict(QUERIES)
    print "\nJBoss Status Queries completed at ",time.asctime( time.localtime(time.time()) ) + ".\n"
