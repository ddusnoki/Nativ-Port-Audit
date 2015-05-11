#!/usr/bin/python
#
# (mong) v0.1rc1 2014.11.19
# simon.szumylowicz@nativ.tv
#
# known issues:
# - crashes sometimes :(
# - deal with false positives
#
# requirements:
# - python-nmap
# - python-termcolor
# - python-pymongo >= 2.4
# - python-yaml
# - python-daemon
# + an instance of MongoDB
#
# todo for v0.2:
# - wrap the whole thing in a class, with init() and main_loop() (and add terminate()), use daemon.DaemonRunner
# - handle SIGTERM (end main loop, re-run setup)
#
# todo for v0.3:
# - use inotify to scan config file changes
#
# todo for v0.4:
# - add basic http status check

import time
import logging
import smtplib
import socket
import yaml
import nmap
import daemon
from email.mime.text import MIMEText
from email.header import Header
from termcolor import colored
from pymongo import MongoClient, ASCENDING, DESCENDING
from human_time import humanize_time

# read config, define some consts
config_file = open("config.yaml")
config = yaml.load(config_file)
config_file.close()

hosts = config['hosts']
PORT_RANGE_START    = config['settings']['port_range_start']
PORT_RANGE_END      = config['settings']['port_range_end']
PORT_RANGE          = str(PORT_RANGE_START) + "-" + str(PORT_RANGE_END)

# logging setup
level = logging.getLevelName(config['settings']['loglevel'])
logger = logging.getLogger(__name__)
logger.setLevel(level)

filehandler = logging.FileHandler("mong.log")
filehandler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))

consolehandler = logging.StreamHandler()
consolehandler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))

logger.addHandler(filehandler)
logger.addHandler(consolehandler)

# mongodb setup
logger.debug('connecting to mongodb at %s:27017, database: %s, collection: %s' % (config['settings']['mongodb']['server'], config['settings']['mongodb']['database'], config['settings']['mongodb']['collection']))
mongo = MongoClient('mongodb://' + config['settings']['mongodb']['server'] + ':27017')
db = mongo[config['settings']['mongodb']['database']]
alerts = db[config['settings']['mongodb']['collection']]
logger.debug('seting up index')
index = alerts.create_index([("host", ASCENDING), ("port", ASCENDING) ])

logger.debug('email alerts are sent to %s' % config['settings']['email'])
logger.debug('monitoring the following hosts: %s' % hosts)

def human_time(number):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(number))

def remove_dots(string_):
    newstring = string_.replace('.', '_')
    return newstring

def add_dots(string_):
    newstring = string_.replace('_', '.')
    return newstring

def email_alert(name, host, port, state, start, stop):
    mailserver = smtplib.SMTP('localhost')
    if port == -1:
        logger.debug('constructing host down email for %s' % name)
        if state == "open":
            subject = "Alert cleared: %s is back up" % name
            body = "%s (%s) is back online.\n\nFirst noticed at %s.\nLasted for %s." % (name, host, human_time(start), humanize_time(stop - start))
        if state == "closed":
            subject = "Alert: %s is DOWN!" % name
            body = "%s (%s) is down!\n\nNoticed at %s." % (name, host, human_time(start))
    else:
        logger.debug('constructing port change email for %s' % name)
        if port in hosts[name]['ports']:
            logger.debug('port %i is allowed and %s' % (port, state))
            if state == "open":
                subject = "Alert cleared: port %i on %s is open" % (port, name)
                body = "Port %i on %s (%s) is now open.\n\nFirst noticed at %s.\nLasted for %s.\n\nExpected open ports for this host: %s" % (port, name, host, human_time(start), humanize_time(stop - start), hosts[name]['ports'])
            if state == "closed":
                subject = "Alert: port %i on %s is closed!" % (port, name)
                body = "Port %i on %s (%s) is now CLOSED!\n\nNoticed at %s.\n\nExpected open ports for this host: %s" % (port, name, host, human_time(start), hosts[name]['ports'])
        else:
            logger.debug('port %i is not allowed and is %s' % (port, state))
            if state == "open":
                subject = "Alert: port %i on %s is open!" % (port, name)
                body = "Port %i on %s (%s) is now OPEN!\n\nFirst noticed at %s.\n\nExpected open ports for this host: %s" % (port, name, host, human_time(start), hosts[name]['ports'])
            if state == "closed":
                subject = "Alert cleared: port %i on %s is closed" % (port, name)
                body = "Port %i on %s (%s) is now closed.\n\nFirst noticed at %s\nLasted for %s.\n\nExpected open ports for this host: %s" % (port, name, host, human_time(start), humanize_time(stop - start), hosts[name]['ports'])

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = "port scanner <nativ@" + socket.getfqdn() + ">"
    msg['To'] = config['settings']['email']
    if not 'cleared' in subject:
        msg['X-Priority'] = '2'
    logger.debug("host is live? %s" % hosts[name]['live'])
    if hosts[name]['live'] == True:
        logger.debug("sending email notification to %s", config['settings']['email'])
        mailserver.sendmail("port scanner <nativ@" + socket.getfqdn() + ">", config['settings']['email'], msg.as_string())
    else:
        logger.debug("not sending email, host is not live")
    mailserver.quit()

def add_alert(name, host, port, state):
    if not find_alert(host, port, state):
        curtime = time.time()
        alerts.insert( { "name": name, "host": remove_dots(host), "port": port, "state": state, "start": curtime, "stop": 0 } )
        email_alert(name, host, port, state, time.time(), 0)
	if port == -1:
	    logger.error('%s (%s) is DOWN!' % (name, host))
	else:
	    logger.error('%s (%s): port %s is %s!' % (name, host, port, state))

def clear_alert(host, port, state):
    for alert in alerts.find( { "host": remove_dots(host), "port": port, "state": state, "stop": 0 } ):
        alert['stop'] = time.time()
        alerts.save(alert)
        outage = alert['stop'] - alert['start']
        # invert state for email message
        if state == "open":
            email_alert(name ,host, port, "closed", alert['start'], alert['stop'])
        else:
            email_alert(name, host, port, "open", alert['start'], alert['stop'])
        if alert['port'] == -1:
            logger.warn('%s (%s) is UP, alert cleared after %s' % (alert['name'], add_dots(alert['host']), humanize_time(outage)))
        else:
            logger.warn('%s (%s): port %s is no longer %s, alert cleared after %s' % (alert['name'], add_dots(alert['host']), alert['port'], alert['state'], humanize_time(outage)))

def find_alert(host, port, state):
    for alert in alerts.find( { "host": remove_dots(host), "port": port, "state": state, "stop": 0 } ):
        return alert

#print ("clearing active alerts")
#alerts.remove( { "stop": 0 } )

logger.warn("active alerts:")
for alert in alerts.find( { "stop": 0 } ):
    if alert['port'] == -1:
        logger.warn('%s (%s) is DOWN! since %s (%s ago)' % (alert['name'], add_dots(alert['host']), human_time(alert['start']), humanize_time(int(time.time() - alert['start']))))
    else:
        logger.warn('%s (%s): port %s is %s since %s (%s ago)' % (alert['name'], add_dots(alert['host']), alert['port'], alert['state'], human_time(alert['start']), humanize_time(int(time.time() - alert['start']))))

logger.debug('entering main loop')
with daemon.DaemonContext(files_preserve=[filehandler.stream]):
    while True:
        for name in hosts:
            nm = nmap.PortScanner()
            host = hosts[name]['ip']
            allowed_ports = hosts[name]['ports']
	
            logger.info('---------------- %s (%s) -----------------------' % (name, host) )
            logger.info('%s (%s): scanning ports: %i - %i' % (name, host, PORT_RANGE_START, PORT_RANGE_END))
            logger.info('%s (%s): allowed ports: %s' % (name, host, allowed_ports))

            try:    
                # strangely enough, by default python-nmap scans with -sV...
                # we don't really need that so setting arguments to an empty string
		nm.scan(host, PORT_RANGE, arguments='')
                logger.debug(nm.command_line())
		logger.debug('%s (%s) is %s!' % (name, host, nm[host].state()))
                open_ports = []
        	ports = nm[host]['tcp'].keys()
		ports.sort()
                for i in ports:
                    if nm[host]['tcp'][i]['state'] == 'open':
                        open_ports.append(i)
		logger.info('%s (%s): open ports: %s' % (name, host, open_ports))
		
                clear_alert(host, -1, 'down')

		for port in range(PORT_RANGE_START, PORT_RANGE_END):
			if port in allowed_ports: # allowed
				if port in open_ports: # open
                                    if find_alert(host, port, 'closed'):
                                         clear_alert(host, port, 'closed')
				else: # closed
					add_alert(name, host, port, 'closed')
			else: # not allowed
				if port in open_ports: # open
					add_alert(name, host, port, 'open')
				else: # closed
                                    if find_alert(host, port, 'open'):
                                        clear_alert(host, port, 'open')
            except KeyError as exkey:
		add_alert(name, host, -1, 'down')

            logger.info('---------------------------------------')
            logger.debug("total mongo alerts:  %i" % alerts.count())
            logger.debug("active mongo alerts: %i" % alerts.find({"stop": 0}).count())
