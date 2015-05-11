#!/usr/bin/env python

import nmap
import yaml
import sys
import socket

config_file = open('config.yaml')
config = yaml.load(config_file)
config_file.close()

PORT_RANGE = str(config['settings']['port_range_start']) + '-' + str(config['settings']['port_range_end'])

nm = nmap.PortScanner()
hosts = []
nm.scan(sys.argv[1], PORT_RANGE, arguments='')

for host in nm.all_hosts():
    hosts.append(str(host))

# stolen from http://www.secnetix.de/olli/Python/tricks.hawk#sortips
for i in range(len(hosts)):
        hosts[i] = "%3s.%3s.%3s.%3s" % tuple(hosts[i].split("."))
hosts.sort()
for i in range(len(hosts)):
        hosts[i] = hosts[i].replace(" ", "")

for host in hosts:
    print('        %s:' % host)
    print('                ip: %s ' % host)
    ports = []
    for port in nm[host]['tcp'].keys():
        if nm[host]['tcp'][port]['state'] == 'open':
            ports.append(port)
    ports.sort()
    print('                ports: %s' % ports)
    print('                live: no')
