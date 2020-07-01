import time
import subprocess
import select
import mcrpc
import socket
import curses
from datetime import datetime
import prelude
import re

stdscr = curses.initscr()
curses.noecho()
stdscr.nodelay(1) 

#Settings parameters to query multichain
wait = 30
iTime = int(round(time.time()))
start = 0
count = 100
localOrdering = False
verbose = True

# Create a new Prelude client.
clientPrelude = prelude.ClientEasy("MySensor")
clientPrelude.start()

#Create the multichain rpc client
client = mcrpc.RpcClient('127.0.0.1', '6736', 'test', 'test')
info = client.getinfo()
stream = "snort"

hostname = socket.gethostname()
ipAddress = socket.gethostbyname(hostname)


key = hostname+"-prelude"
client.subscribe(stream)

priority = ["info", "low", "medium", "high"]

# Check the last item index 
items = client.liststreamkeyitems(stream,key,verbose,1,start,not localOrdering)
if len(items)>0:
	start = int(items[0]["data"]["text"])

stdscr.addstr(0,0,"Press \"q\" or \"Q\" to exit...")
try :
	while True:
		nTime = int(round(time.time()))
		c = stdscr.getch()
		if nTime-iTime>= 30:
			iTime = nTime
			alerts = client.liststreamitems(stream,verbose,count,start,localOrdering)
			if len(alerts)>0:			
				i = 0
				for alert in alerts:
					s = alert["data"]["text"]
					i = i + 1

					#conversion
					# Create the IDMEF message
					idmef = prelude.IDMEF()

					m = re.match(r'^([0-9:./-]+)\s+ \[(.+?)\] \[(.+?)\] (.+?) \[(.+?)\] \[Classification: (.+?)\] \[Priority: (\d+)] \{(.+?)\} (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\n?', s)

					if m is None:
						m = re.match(r'^([0-9:./-]+)\s+ \[(.+?)\] \[(.+?)\] (.+?) \[(.+?)\] \[Classification: (.+?)\] \[Priority: (\d+)] \{(.+?)\} (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\n?', s)
						
						if m is None:
							continue
						else:
						
							idmef.set("alert.target(0).node.address(0).address", m.group(10))
						
					else:
						
						idmef.set("alert.source(0).service.port", int(m.group(10)))
						idmef.set("alert.target(0).node.address(0).address", m.group(11))
						idmef.set("alert.target(0).service.port", int(m.group(12)))	
					

					
					
					# Created time
					idmef.set( "alert.create_time", datetime.strptime(m.group(1),'%m/%d/%y-%H:%M:%S.%f').strftime('%Y-%m-%d'))

					# Priority
					idmef.set( "alert.assessment.impact.severity", priority[int(m.group(7))])

					# Description
					idmef.set( "alert.assessment.impact.description", m.group(4))
			    
					# Classification
					idmef.set( "alert.classification.text", m.group(6))

					# Source
					idmef.set("alert.source(0).node.address(0).address", m.group(9))
					idmef.set("alert.source(0).service.protocol", m.group(8))

					# Target 
					idmef.set("alert.target(0).service.protocol", m.group(8))
					
					##envoie vers prelude

					clientPrelude.sendIDMEF(idmef)

				start = start + i

		if c==ord('q') or c==ord('Q'):
			client.publish(stream, key, {"text": str(start)})		
			break


finally:
	curses.endwin()
