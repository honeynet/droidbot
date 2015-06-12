__author__ = 'liyc'
# Example from https://github.com/shirish57/DroidBox_DroidBOT/blob/master/scripts/DroidBOT/gps.py
# Dynamically changes GPS coordinate values in emulator.

import getpass
import sys
import telnetlib
import time
import random

HOST = "localhost"		# Host address
tn = telnetlib.Telnet(HOST,5554)	# First emulator's port 5554

lat=random.uniform(20, 70)	# Get random Latitude
lon=random.uniform(20, 70)	# Get random Longitude

tn.read_until("OK",5)		# Wait till 'OK'. Timeout after 5 seconds

while True:	# Infinite loop till analysis stops
	lat_offset=random.random()	# Offset to make it more realistic by adding precision problem in latitude
	lon_offset=random.random()	# Offset to make it more realistic by adding precision problem in longitude
	latitude=lat+lat_offset		# Final Latitude
	longitude=lon+lon_offset	# Final Longitude
	tn.write("geo fix "+str(latitude)+" "+str(longitude)+"\n")
	tn.read_until("OK",5)	# Wait till 'OK'. Timeout after 5 seconds
	time.sleep(5)	# GPS Updated every 5 seconds