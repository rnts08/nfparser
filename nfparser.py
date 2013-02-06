#! /usr/bin/env python
import os
import sys
import socket
import time
import operator
import subprocess
from string import digits

"""
 Configuration
"""

""" Number of top-records to show """
num_top = 15

""" List of our networks """
networks = ['1.2.3.4/23','4.3.2.1/24']

""" List of interface ID (snmp ifIndex) and names (>=8 char) """
interfaces = {67:'ge-0/0/7', 55:'NL-IX', 17:'ae0.71'}

""" Netflow data directories """
netflow_data_dir = '/var/flow/'
netflow_data_routers = ['routerN', 'routerY']

""" Nfdump binary path """
nfdump = '/usr/bin/nfdump'

""" ASNumber description file """
asnumfile = '/tmp/asn.map'

"""
 Helper methods
"""

def createFileName():
    today = time.strftime('%Y-%m-%d')
    files = []
    for directory in os.listdir(netflow_data_dir):
        if directory in netflow_data_routers:
            files += os.listdir(netflow_data_dir + directory + '/' + today)
    return today + '/' + sorted(set(files))[-1]

def createDirectoryString():
    netflow_dir = netflow_data_dir
    for router in netflow_data_routers:
        netflow_dir += router + ':'
    return netflow_dir[:-1]

def createNetworkString(net_dir):
    net_filter_string = ''
    if len(networks) > 1:
        for index, network in enumerate(networks):
            if index == len(networks)-1:
                net_filter_string += net_dir + ' net ' + network
            else:
                net_filter_string += net_dir + ' net ' + network + ' or '
        return net_filter_string
    else:
        return net_dir + ' net '+networks[0]

def convIfIdToName(ifIndex):
    if ifIndex in interfaces:
        return interfaces[ifIndex]
    return 'UNKNOWN'

def convBytesToSi(bytes):
    bytes = float(bytes)
    sfix = ['B','K','M','G','T','P']
    rtimes = 0
    while (bytes/1024) > 1: 
        bytes = bytes/1024 
        rtimes += 1

    return [round(bytes,2), sfix[rtimes]]

def createCommand(direction='dst'):
    if direction == 'dst':
        aggregation_keys = 'dstas,outif'
        net_dir = 'src'
        fmt_dir = 'das'
        nif = 'out'
    else:
        aggregation_keys = 'srcas,inif'
        net_dir = 'dst'
        fmt_dir = 'sas'
        nif = 'in'

    command = nfdump + ' -q -N -A ' + aggregation_keys + ' -r ' + createFileName() + ' -M ' + createDirectoryString() + ' -m \'' + createNetworkString(net_dir) + '\' -o \'fmt: %'+fmt_dir+', %byt, %bps, %'+nif+'\''
    return command

"""
 AsScoreBoard + Helpers
"""
def createAsScoreBoard(direction):
    AsScoreBoard = []
    p = subprocess.Popen(createCommand(direction), shell=True, stdout=subprocess.PIPE)
    for line in p.stdout:
        if line == '\n': break
        values = line.split(',')
        asn = values[0].strip()
        AsScoreBoard.append({'asn': asn,
                             'as-name': asToName(asn), 
                             'bytes': int(values[1].strip()),
                             'bps': int(values[2].strip()),
                             'if': int(values[3].strip())
                             })
    return AsScoreBoard

def SortAsScoreBoard(scoreboard, order='desc', field='bytes'):
    if order == 'asc':
        return sorted(scoreboard, key=operator.itemgetter(field))
    else:
        return sorted(scoreboard, key=operator.itemgetter(field), reverse=True)

"""
 ASN Lookup 
"""
def asToName(asnum,le=34):
    tmpf = asnumfile
    with open(tmpf) as fh:
        for line in fh:
            l = line.split(':')
            if l[0] == str(asnum):
                # we found the as in tmpf, return fast!
                return l[1].rstrip('\n')[:le]
                break

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

"""
 Main function
"""
def main():
    for direction in ('dst','src'):
        l = SortAsScoreBoard(createAsScoreBoard(direction))
        lcount = 0
        print '*' * 80
        print 'Top '+direction+' ASN Interface/Total/Speed ('+str(len(l))+'):'
        for asdict in l:
            if lcount >= num_top:
                print ""
                lcount = 0
                break
            
            asn = asdict['asn']
            asname = asdict['as-name']
            bytes = convBytesToSi(asdict['bytes'])
            bps = convBytesToSi(asdict['bps'])
            real_if = convIfIdToName(asdict['if'])
            print '[AS%-5d] %-35s: %-7s :% 7.2f%sB / % 7.2f%sbps' % (int(asn), asname, real_if, bytes[0], bytes[1], bps[0], bps[1])
            lcount += 1

def search(search_asn):
    print 'Searching for AS'+search_asn+'...'
    for direction in ('dst','src'):
        l = SortAsScoreBoard(createAsScoreBoard(direction))
        for asdict in l:
            if search_asn == asdict['asn']:
                print 'Found AS'+search_asn+' in the \''+direction+'\' direction'
                asn = asdict['asn']
                asname = asdict['as-name']
                bytes = convBytesToSi(asdict['bytes'])
                bps = convBytesToSi(asdict['bps'])
                real_if = convIfIdToName(asdict['if'])
                print '[AS%-5d] %-35s: %-7s :% 7.2f%sB / % 7.2f%sbps' % (int(asn), asname, real_if, bytes[0], bytes[1], bps[0], bps[1])

"""
 Program entry
"""
if __name__ == '__main__':
    if len(sys.argv) > 1:
        if len(sys.argv) < 2:
            sys.exit('Usage: %s as-number' % sys.argv[0])
        asn = ''.join(c for c in sys.argv[1] if c in digits)
        search(asn)
    else:
        main()
