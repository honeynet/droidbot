__author__ = 'liyc'
# Example from https://github.com/shirish57/DroidBox_DroidBOT/blob/master/scripts/DroidBOT/accelerometer.py
# Dynamically changes accelerometer values in emulator.

import getpass
import sys
import telnetlib
import time
import random

HOST = "localhost"		# Host address
tn = telnetlib.Telnet(HOST,5554)	# First emulator's port 5554

x=random.uniform(0, 90)	# Get random X Coordinate
y=random.uniform(0, 90)	# Get random Y Coordinate
z=random.uniform(0, 90)	# Get random Z Coordinate

tn.read_until("OK",5)		# Wait till 'OK'. Timeout after 5 seconds

while True:	# Infinite loop till analysis stops
	tn.write("sensor set acceleration "+str(x)+":"+str(y)+":"+str(z)+"\n")
	x=random.uniform(0, 90)	# Get random X Coordinate
	y=random.uniform(0, 90)	# Get random Y Coordinate
	z=random.uniform(0, 90)	# Get random Z Coordinate
	tn.read_until("OK",5)	# Wait till 'OK'. Timeout after 5 seconds
	time.sleep(1)	# Accelerometer readings Updated every second