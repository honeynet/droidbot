import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime
from subprocess import call, PIPE, Popen
from threading import Thread
from xml.dom import minidom

from utils import AXMLPrinter

# I have to modify DroidBox scripts to let it work with droidbot
__author__ = 'yuanchun'

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

"""
Analyze dynamically Android applications
This script allows you to analyze dynamically Android applications.
It installs, runs, and analyzes Android applications.
At the end of each analysis, it outputs the Android application's characteristics in JSON.
Please keep in mind that all data received/sent,
read/written are shown in hexadecimal since the handled data can contain binary data.
"""

tags = {0x1: "TAINT_LOCATION", 0x2: "TAINT_CONTACTS", 0x4: "TAINT_MIC", 0x8: "TAINT_PHONE_NUMBER",
        0x10: "TAINT_LOCATION_GPS", 0x20: "TAINT_LOCATION_NET", 0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
        0x100: "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS", 0x400: "TAINT_IMEI", 0x800: "TAINT_IMSI",
        0x1000: "TAINT_ICCID", 0x2000: "TAINT_DEVICE_SN", 0x4000: "TAINT_ACCOUNT", 0x8000: "TAINT_BROWSER",
        0x10000: "TAINT_OTHERDB", 0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE", 0x80000: "TAINT_CALL_LOG",
        0x100000: "TAINT_EMAIL", 0x200000: "TAINT_CALENDAR", 0x400000: "TAINT_SETTINGS"}


class LostADBException(Exception):
    pass


class DroidBox(object):
    def __init__(self, droidbot=None, output_dir=None):
        self.sensitive_behaviors = []
        self.enabled = True

        self.droidbot = droidbot
        self.logcat = None

        self.application = None
        self.apk_name = None
        self.apk_hashes = None
        self.applicationStarted = 0

        self.is_counting_logs = False
        self.timer = None

        self.state_monitor = None
        if self.droidbot:
            self.state_monitor = self.droidbot.device.state_monitor
        else:
            from droidbot.adapter.process_monitor import ProcessMonitor
            self.state_monitor = ProcessMonitor()

        if output_dir:
            self.output_dir = output_dir
            if not os.path.exists(self.output_dir):
                os.mkdir(self.output_dir)
        else:
            # Posibility that no output-files is generated
            self.output_dir = None

    def set_apk(self, apk_name):
        if not self.enabled:
            return
        if apk_name is None:
            return
        # APK existing?
        if not os.path.isfile(apk_name):
            print("File %s not found" % apk_name)
            sys.exit(1)

        self.apk_name = os.path.abspath(apk_name)

        self.application = Application(apk_name)
        ret = self.application.processAPK()

        # Error during the APK processing?
        if ret == 0:
            print("Failed to analyze the APK. Terminate the analysis.")
            sys.exit(1)

        main_activity = self.application.getMainActivity()
        package_name = self.application.getPackage()
        self.apk_hashes = self.application.getHashes()

        # No Main activity found? Return an error
        if main_activity is None:
            print("No activity to start. Terminate the analysis.")
            sys.exit(1)

        # No packages identified? Return an error
        if package_name is None:
            print("No package found. Terminate the analysis.")
            sys.exit(1)

        # Execute the application
        call(["adb", "logcat", "-c"])
        ret = call(['monkeyrunner', 'monkeyrunner.py', apk_name,
                    package_name, main_activity], stderr=PIPE,
                   cwd=os.path.dirname(os.path.realpath(__file__)))

        if ret == 1:
            print("Failed to execute the application.")
            sys.exit(1)

        print("Starting the activity %s..." % main_activity)

        # By default the application has not started
        self.applicationStarted = 0
        stringApplicationStarted = "Start proc %s" % package_name

        # Open the adb logcat
        if self.logcat is None:
            self.logcat = Popen(["adb", "logcat", "-v", "threadtime", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)

        # Wait for the application to start
        while 1:
            try:
                logcatInput = self.logcat.stdout.readline()
                if not logcatInput:
                    raise Exception("We have lost the connection with ADB.")

                # Application started?
                if (stringApplicationStarted in logcatInput):
                    self.applicationStarted = 1
                    break
            except:
                break

        if (self.applicationStarted == 0):
            print("Analysis has not been done.")
            # Kill ADB, otherwise it will never terminate
            os.kill(self.logcat.pid, signal.SIGTERM)
            sys.exit(1)

        print("Application started")

    def start_unblocked(self, duration=0):
        droidbox_thread = threading.Thread(target=self.start_blocked, args=(duration,))
        droidbox_thread.start()

    def stop(self):
        self.enabled = False
        if self.timer and self.timer.isAlive():
            self.timer.cancel()
        if self.logcat is not None:
            self.logcat.terminate()
            self.logcat = None
        if self.state_monitor:
            self.state_monitor.stop()

    def start_blocked(self, duration=0):
        if not self.enabled:
            return
        # curses.setupterm()
        # sys.stdout.write(curses.tigetstr("clear"))
        sys.stdout.flush()
        call(["adb", "wait-for-device"])
        call(['adb', 'logcat', '-c'])

        print " ____                        __  ____"
        print "/\  _`\               __    /\ \/\  _`\\"
        print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"
        print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\"
        print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
        print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
        print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

        counter = CountingThread()
        counter.start()

        if duration:
            self.timer = threading.Timer(duration, self.stop)
            self.timer.start()

        if self.logcat is None:
            self.logcat = Popen(["adb", "logcat", "-v", "threadtime", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Collect DroidBox logs
        self.is_counting_logs = True
        self.lastScreenshot = 0
        first_log_time = None

        fd2path = {}

        while self.enabled:
            try:
                if self.output_dir and (time.time() - self.lastScreenshot) >= 5:
                    # Take screenshots every 5 seconds.
                    os.system("adb shell screencap -p | sed 's/\r$//' > %s" % os.path.join(self.output_dir, "screen") \
                              + "_$(date +%Y-%m-%d_%H%M%S).png")
                    self.lastScreenshot = time.time()

                logcatInput = self.logcat.stdout.readline()
                if not logcatInput:
                    raise LostADBException("We have lost the connection with ADB.")

                log_data = parse_log(logcatInput)

                if log_data is None or not log_data['content'].startswith("DroidBox:"):
                    continue

                log_time = log_data['datetime']
                if first_log_time is None:
                    first_log_time = log_time
                log_delta_seconds = (log_time - first_log_time).total_seconds()

                log_content = json.loads(decode(log_data['content'][10:]))

                log_process_names = self.state_monitor.get_names_by_pid(log_data['pid'])
                log_process_name = "->".join(log_process_names)

                for log_type in log_content:
                    log_detail = log_content[log_type]
                    if log_type == "FdAccess":
                        path = hexToStr(log_detail['path'])
                        fd2path[log_detail['id']] = path
                        log_detail['path'] = path
                    if log_type == "FileRW" and log_detail['id'] in fd2path:
                        log_detail['path'] = fd2path[log_detail['id']]
                    if log_type == "DataLeak":
                        log_detail['tag'] = getTags(int(log_detail['tag'], 16))
                        if log_detail['sink'] == "File" and log_detail['id'] in fd2path:
                            log_detail['path'] = fd2path[log_detail['id']]

                    log_dict = {"type": log_type,
                                "time": log_delta_seconds,
                                "process": log_process_name,
                                "detail": log_detail}

                    if self.filter_noises(log_dict):
                        continue

                    self.sensitive_behaviors.append(log_dict)
                    counter.increaseCount()
            except KeyboardInterrupt:
                break
            except LostADBException:
                break
            except Exception as e:
                print(e.message)
                continue

        self.is_counting_logs = False
        counter.stopCounting()
        counter.join()
        # Kill ADB, otherwise it will never terminate
        self.stop()
        self.logcat = None

        print json.dumps(self.get_output())
        if self.output_dir is None:
            return
        with open(os.path.join(self.output_dir, "analysis.json"), "w") as json_file:
            json_file.write(json.dumps(self.get_output(), sort_keys=True, indent=4))

    def get_output(self):
        # Done? Store the objects in a dictionary, transform it in a dict object and return it
        output = dict()

        # Sort the items by their key
        output["recvsaction"] = self.application.getRecvsaction()
        output["permissions"] = self.application.getPermissions()
        output["hashes"] = self.apk_hashes
        output["apkName"] = self.apk_name
        output["sensitiveBehaviors"] = self.sensitive_behaviors
        return output

    def get_counts(self):
        output = dict()

        for behavior in self.sensitive_behaviors:
            output[behavior['type']] = 0
        for behavior in self.sensitive_behaviors:
            output[behavior['type']] += 1

        output["sum"] = sum(output.values())
        return output

    def filter_noises(self, log_dict):
        """
        filter use less noises from log
        :param log_dict: DroidBox log in dict format
        :return: boolean
        """
        if log_dict['type'] in ["FdAccess", "FileRW"]:
            if log_dict['detail']['path'].startswith("socket") or log_dict['detail']['path'].startswith("pipe"):
                return True
        return False


class CountingThread(Thread):
    """
    Used for user interface, showing in progress sign
    and number of collected logs from the sandbox system
    """

    def __init__(self):
        """
        Constructor
        """

        Thread.__init__(self)
        self.stop = False
        self.logs = 0

    def stopCounting(self):
        """
        Mark to stop this thread
        """
        self.stop = True

    def increaseCount(self):
        self.logs += 1

    def run(self):
        """
        Update the progress sign and
        number of collected logs
        """

        signs = ['|', '/', '-', '\\']
        counter = 0
        while 1:
            sign = signs[counter % len(signs)]
            sys.stdout.write("[%s] Collected %s sandbox logs (Ctrl-C to view logs)\r" % (sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter += 1
            if self.stop:
                print "[%s] Collected %s sandbox logs (Ctrl-C to view logs)" % ("*", str(self.logs))
                break


class Application:
    """
    Used for extracting information of an Android APK
    """

    def __init__(self, filename):
        self.filename = filename
        self.packageNames = []
        self.enfperm = []
        self.permissions = []
        self.recvs = []
        self.activities = {}
        self.recvsaction = {}

        self.mainActivity = None

    def processAPK(self):
        xml = {}
        error = True
        try:
            zip = zipfile.ZipFile(self.filename)

            for i in zip.namelist():
                if i == "AndroidManifest.xml":
                    try:
                        xml[i] = minidom.parseString(zip.read(i))
                    except:
                        xml[i] = minidom.parseString(AXMLPrinter(zip.read(i)).getBuff())

                    for item in xml[i].getElementsByTagName('manifest'):
                        self.packageNames.append(str(item.getAttribute("package")))

                    for item in xml[i].getElementsByTagName('permission'):
                        self.enfperm.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('uses-permission'):
                        self.permissions.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('receiver'):
                        self.recvs.append(str(item.getAttribute("android:name")))
                        for child in item.getElementsByTagName('action'):
                            self.recvsaction[str(item.getAttribute("android:name"))] = (
                                str(child.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('activity'):
                        activity = str(item.getAttribute("android:name"))
                        self.activities[activity] = {}
                        self.activities[activity]["actions"] = list()

                        for child in item.getElementsByTagName('action'):
                            self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))

                    for activity in self.activities:
                        for action in self.activities[activity]["actions"]:
                            if action == 'android.intent.action.MAIN':
                                self.mainActivity = activity
                    error = False
                    break

            if not error:
                return 1
            else:
                return 0

        except:
            return 0

    def getEnfperm(self):
        return self.enfperm

    def getRecvsaction(self):
        return self.recvsaction

    def getMainActivity(self):
        return self.mainActivity

    def getActivities(self):
        return self.activities

    def getPermissions(self):
        return self.permissions

    def getRecvActions(self):
        return self.recvsaction

    def getPackage(self):
        # One application has only one package name
        return self.packageNames[0]

    def getHashes(self, block_size=2 ** 8):
        """
        Calculate MD5,SHA-1, SHA-256
        hashes of APK input file
        @param block_size:
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        f = open(self.filename, 'rb')
        while True:
            data = f.read(block_size)
            if not data:
                break

            md5.update(data)
            sha1.update(data)
            sha256.update(data)
        return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]


def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')


def getTags(tagParam):
    """
    Retrieve the tag names
    """

    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound


def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """

    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i + 2], 16)))
    return unicode(''.join(bytes), errors='replace')


def interruptHandler(signum, frame):
    """
    Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'

    """
    raise KeyboardInterrupt


# logcat regex, which will match the log message generated by `adb logcat -v threadtime`
LOGCAT_THREADTIME_RE = re.compile('^(?P<date>\S+)\s+(?P<time>\S+)\s+(?P<pid>[0-9]+)\s+(?P<tid>[0-9]+)\s+'
                                  '(?P<level>[VDIWEFS])\s+(?P<tag>[^:]*):\s+(?P<content>.*)$')


def parse_log(log_msg):
    """
    parse a logcat message
    the log should be in threadtime format
    @param log_msg:
    @return:
    """
    m = LOGCAT_THREADTIME_RE.match(log_msg)
    if not m:
        return None
    log_dict = {}
    date = m.group('date')
    time = m.group('time')
    log_dict['pid'] = m.group('pid')
    log_dict['tid'] = m.group('tid')
    log_dict['level'] = m.group('level')
    log_dict['tag'] = m.group('tag')
    log_dict['content'] = m.group('content')
    datetime_str = "%s-%s %s" % (datetime.today().year, date, time)
    log_dict['datetime'] = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")

    return log_dict


def main():
    argv = sys.argv
    if len(argv) < 2 or len(argv) > 3:
        print("Usage: droidbox.py filename.apk <duration in seconds>")
        sys.exit(1)

    duration = 0

    # Duration given?
    if len(argv) == 3:
        duration = int(argv[2])

    apkName = sys.argv[1]

    # APK existing?
    if os.path.isfile(apkName) == False:
        print("File %s not found" % argv[1])
        sys.exit(1)

    droidbox = DroidBox()
    droidbox.set_apk(apkName)
    droidbox.start_blocked(duration)
    # droidbox.get_output()


if __name__ == "__main__":
    main()
