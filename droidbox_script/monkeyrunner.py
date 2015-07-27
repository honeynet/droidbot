################################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com and Laurent Delosieres ldelosieres@hispasec.com
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

import sys
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice

import subprocess
import logging

apkName = sys.argv[1]
package = sys.argv[2]
activity = sys.argv[3]

device = None

#logger = logging.getLogger(__name__)

while device == None:
	try:
		print("Waiting for the device...")
		device = MonkeyRunner.waitForConnection(3)
	except:
		pass

#Install the package
print("Installing the application %s..." % apkName)
device.installPackage(apkName)

# sets the name of the component to start
if "." in activity:
	if activity.startswith('.'):
		runComponent = "%s/%s%s" % (package, package, activity)
	else:
		runComponent = "%s/%s" % (package, activity)
else:
	runComponent = "%s/%s.%s" % (package, package, activity)

print("Running the component %s..." % (runComponent))

# Runs the component
p = subprocess.Popen(["adb", "shell", "am", "start", "-n", runComponent], stdout=subprocess.PIPE)
out, err = p.communicate()

#Activity not started?
if "Error type" in out:
	sys.exit(1)
else:
	sys.exit(0)
