#! /usr/bin/env python
import os
import sys
import socket
import time
import operator
import subprocess

# timer with print
def print_timing(func):
    def wrapper(*arg):
        t1 = time.clock()
        res = func(*arg)
        t2 = time.clock()
        print '%s took %0.3fms' % (func.func_name, (t2-t1)*1000.0)
        return res
    return wrapper

# create a dir/filename from date/datetime-strings (dir-fileformat matching nfcapd's) with the filecreation lag.
# debug: @print_timing
def createFileName():
    hourpart = int(time.strftime('%H'))
    minutepart = int(round(float(time.strftime('%M')),-1))-10
    if minutepart < 0: 
        minutepart = '00'
    elif minutepart == 0:
        minutepart = '55'
        hourpart -= 1
    return time.strftime('%Y-%m-%d')+'/'+'nfcapd.'+time.strftime('%Y%m%d')+str(hourpart).rjust(2,'0')+str(minutepart)

# createAsScoreBoard(direction) - creates a scoreboard of current known ases in 'direction'
# debug: @print_timing
def createAsScoreBoard(direction):
    fdirs = ## Something like this: '/var/flow/router1:router2:router3'
    nfdump = ## Path to Binary: '/usr/bin/nfdump'
    fname = createFileName()
    network = ## My Own IP-range '1.2.3.0/24'
    AsScoreBoard = []

    # determine direction of traffic flow
    if direction == 'dst':
        agg_key = 'dstas'
        net_dir = 'src'
        fmt_dir = 'das'
    else:
        agg_key = 'srcas'
        net_dir = 'dst'
        fmt_dir = 'sas'

    pcmd = nfdump+" -q -N -A "+agg_key+" -r "+fname+" -M "+fdirs+" -m '"+net_dir+" net "+network+"' -o 'fmt:%"+fmt_dir+", %byt, %bps'"
    p = subprocess.Popen(pcmd,shell=True,stdout=subprocess.PIPE)
    for line in p.stdout:
        if line == '\n': break
        values = line.split(',')
        asn = values[0].strip()
        AsScoreBoard.append({'asn': asn,
                             'as-name': asToName(asn), 
                             'bytes': int(values[1].strip()),
                             'bps': int(values[2].strip())
                            })
    return AsScoreBoard

# SortAsScoreBoard - Sort the data by field in order:
# debug: @print_timing
def SortAsScoreBoard(data,order='desc',field='bytes'):
    if order == 'asc':
        return sorted(data, key=operator.itemgetter(field))
    else:
        return sorted(data, key=operator.itemgetter(field), reverse=True)

# asToNum(as-number) - returns the as-name from the asnum-map or cyrmu.com
# debug: @print_timing
def asToName(asnum,le=40):
    # filename for the asn-map
    tmpf = '/tmp/asn.map'
    with open(tmpf) as fh:
        for line in fh:
            l = line.split(':')
            if l[0] == str(asnum):
                # we found the as in tmpf, return fast!
                return l[1].rstrip('\n')[:le]
                break

    # no as match was found so we use the internetz(cymru) instead.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('whois.cymru.com', 43))
        s.send(' -f as'+ str(asnum) + '\r\n')
    except:
        return 'unknown'
        pass
    response = ''
    while True:
    		d = s.recv(4096)
        	response += d
    		if d == '':
        		break
            s.close()

    if len(response) > 2:
        with open(tmpf,'a+') as f:
            f.write(str(asnum)+':'+response)
            f.close
    
    return response[:le].rstrip('\n')

# convBytes(bytes) - convert bytes into human readable bytes with suffix
# debug: @print_timing
def convBytes(bytes):
    bytes = float(bytes)	# make sure it's a float
    sfix = ['B','K','M','G','T','P']
    rtimes = 0
    while (bytes/1024) > 1: 
        bytes = bytes/1024 
        rtimes += 1

    return [round(bytes,2), sfix[rtimes]]

# main
if __name__ == '__main__':
    for dire in ('dst','src'):
        l = SortAsScoreBoard(createAsScoreBoard(dire))
        lcount = 0
        print 'Top15 '+dire+' ASN ('+str(len(l))+'):'
        for asdict in l:
            if lcount >= 15:
                print ""
                lcount = 0
                break
            # assign, convert & print
            asn = asdict['asn']
            asname = asdict['as-name']
            bytes = convBytes(asdict['bytes'])
            bps = convBytes(asdict['bps'])
            print '[AS%-6d] %-42s: % 7.2f%sB / % 7.2f%sbps' % (int(asn), asname, bytes[0], bytes[1], bps[0], bps[1])
            # bump counter
            lcount += 1
            
