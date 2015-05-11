#!/usr/bin/python
#
# known issues:
# - reports on open ports on hosts that are down

import time
import yaml
import smtplib
from human_time import humanize_time
from pymongo import MongoClient, ASCENDING, DESCENDING
from email.mime.text import MIMEText
from email.header import Header

config_file = open("/home/solid/nativ-port-audit/config.yaml")
config = yaml.load(config_file)
config_file.close()

hosts = config['hosts']

# mongodb setup
mongo = MongoClient('mongodb://' + config['settings']['mongodb']['server'] + ':27017')
db = mongo[config['settings']['mongodb']['database']]
alerts = db[config['settings']['mongodb']['collection']]

def remove_dots(string_):
    newstring = string_.replace('.', '_')
    return newstring

def add_dots(string_):
    newstring = string_.replace('_', '.')
    return newstring

# active alerts

print 'active alerts in LIVE hosts:'
for host in (y for y in hosts if hosts[y]['live'] == True):
    for alert in alerts.find( { "host": remove_dots(hosts[host]['ip']), "stop": 0 } ).sort([("port", ASCENDING)]):
        if alert['port'] == -1:
                print('- %s (%s) is down since %s' % (alert['name'], add_dots(alert['host']), str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start'])))))
        else:
                print('- %s (%s) has port %i %s since %s' % (alert['name'], add_dots(alert['host']), alert['port'], alert['state'], str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start'])))))
print 
print 'active alerts in non-live hosts:'
for host in (y for y in hosts if hosts[y]['live'] == False):
    for alert in alerts.find( { "host": remove_dots(hosts[host]['ip']), "stop": 0 } ).sort([("port", ASCENDING)]):
        if alert['port'] == -1:
                print('- %s (%s) is down since %s' % (alert['name'], add_dots(alert['host']), str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start'])))))
        else:
                print('- %s (%s) has port %i %s since %s' % (alert['name'], add_dots(alert['host']), alert['port'], alert['state'], str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start'])))))


print '\nlast week:'
print

# last weeks top offenders
alert_list = []
for host in hosts:
    alert_list.append([ host, alerts.find( { "host": remove_dots(hosts[host]['ip']), 'start': { '$gt': time.time() - 604800 }, 'stop': { '$gt': time.time() - 604800 }} ).count()])

# sort by second field :)
alert_list.sort(key=lambda x: x[1], reverse=True)

counter = 1
for i in (y for y in alert_list if y[1] > 0 ):
    print "%i. %s had %s alerts last week" % (counter, i[0], i[1])
    counter += 1

# all alerts started and resolved last week
# 7 days in seconds == 604800
print
for alert in alerts.find( { 'start': { '$gt': time.time() - 604800 }, 'stop': { '$gt': time.time() - 604800 } } ).sort([( 'stop', ASCENDING )]):
    if alert['port'] == -1:
        print('%s %s (%s) was down for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), humanize_time(alert['stop'] - alert['start'])))
    else:
        print('%s %s (%s) port %i was %s for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), alert['port'], alert['state'], humanize_time(alert['stop'] - alert['start'])))

# alerts created over a week ago resolved within last week
print '\nlong standing alerts resolved last week:'
for alert in alerts.find( { 'start': { '$lt': time.time() - 604800 }, 'stop': { '$gt': time.time() - 604800 } } ).sort([( 'stop', ASCENDING )]):
    if alert['port'] == -1:
        print('%s %s (%s) was down for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), humanize_time(alert['stop'] - alert['start'])))
    else:
        print('%s %s (%s) port %i was %s for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), alert['port'], alert['state'], humanize_time(alert['stop'] - alert['start'])))

print '\nlast hour:'
for alert in alerts.find( { 'start': { '$gt': time.time() - 3600}, 'stop': { '$gt': time.time() - 3600} } ).sort([( 'stop', DESCENDING )]):
    print('%s %s (%s) port %i was %s for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), alert['port'], alert['state'], humanize_time(alert['stop'] - alert['start'])))

print '\nlong standing alerts resolved last hour:'
for alert in alerts.find( { 'start': { '$lt': time.time() - 3600 }, 'stop': { '$gt': time.time() - 3600 } } ).sort([( 'stop', ASCENDING )]):
    print('%s %s (%s) port %i was %s for %s' % ( str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(alert['start']))), alert['name'], add_dots(alert['host']), alert['port'], alert['state'], humanize_time(alert['stop'] - alert['start'])))

print
print
