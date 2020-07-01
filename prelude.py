import time
import subprocess
import select
import socket
import curses
from datetime import datetime
import prelude
import re


# Create a new Prelude client.
clientPrelude = prelude.ClientEasy("MySensorx")
clientPrelude.start()

PORT = 12345
IP = "192.168.1.92"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, PORT))


priority = ["info", "low", "medium", "high"]


try :
	while True:
		#reception
		s, addr = sock.recvfrom(1024)
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

finally:
	curses.endwin()
