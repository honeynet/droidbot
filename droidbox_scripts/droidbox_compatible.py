# I have to modify droidbox scripts to let it work with droidbot
# This is a compatible version which generate a report with the same format of original DroidBox
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

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import zipfile
from subprocess import call, PIPE, Popen
from threading import Thread
from xml.dom import minidom

from utils import AXMLPrinter

tags = {0x1: "TAINT_LOCATION", 0x2: "TAINT_CONTACTS", 0x4: "TAINT_MIC", 0x8: "TAINT_PHONE_NUMBER",
        0x10: "TAINT_LOCATION_GPS", 0x20: "TAINT_LOCATION_NET", 0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
        0x100: "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS", 0x400: "TAINT_IMEI", 0x800: "TAINT_IMSI",
        0x1000: "TAINT_ICCID", 0x2000: "TAINT_DEVICE_SN", 0x4000: "TAINT_ACCOUNT", 0x8000: "TAINT_BROWSER",
        0x10000: "TAINT_OTHERDB", 0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE", 0x80000: "TAINT_CALL_LOG",
        0x100000: "TAINT_EMAIL", 0x200000: "TAINT_CALENDAR", 0x400000: "TAINT_SETTINGS"}


class LostADBException(Exception):
    pass


class DroidBox(object):
    def __init__(self, output_dir=None):
        self.sendsms = {}
        self.phonecalls = {}
        self.cryptousage = {}
        self.dexclass = {}
        self.dataleaks = {}
        self.opennet = {}
        self.sendnet = {}
        self.recvnet = {}
        self.closenet = {}
        self.fdaccess = {}
        self.servicestart = {}
        self.accessedfiles = {}
        self.enabled = True

        self.adb = None

        self.application = None
        self.apk_name = None
        self.apk_hashes = None
        self.applicationStarted = 0

        self.is_counting_logs = False
        self.timer = None

        if output_dir:
            self.output_dir = output_dir
            if not os.path.exists(self.output_dir):
                os.mkdir(self.output_dir)
        else:
            #Posibility that no output-files is generated
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

        # No Main acitvity found? Return an error
        if main_activity == None:
            print("No activity to start. Terminate the analysis.")
            sys.exit(1)

        # No packages identified? Return an error
        if package_name == None:
            print("No package found. Terminate the analysis.")
            sys.exit(1)

        # Execute the application
        call(["adb", "logcat", "-c"])
        ret = call(['monkeyrunner', 'monkeyrunner.py', apk_name,
                    package_name, main_activity], stderr=PIPE,
                    cwd=os.path.dirname(os.path.realpath(__file__)))

        if (ret == 1):
            print("Failed to execute the application.")
            sys.exit(1)

        print("Starting the activity %s..." % main_activity)

        # By default the application has not started
        self.applicationStarted = 0
        stringApplicationStarted = "Start proc %s" % package_name

        # Open the adb logcat
        if self.adb is None:
            self.adb = Popen(["adb", "logcat", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)

        # Wait for the application to start
        while 1:
            try:
                logcatInput = self.adb.stdout.readline()
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
            os.kill(self.adb.pid, signal.SIGTERM)
            sys.exit(1)

        print("Application started")

    def start_unblocked(self, duration=0):
        droidbox_thread = threading.Thread(target=self.start_blocked, args=(duration,))
        droidbox_thread.start()

    def stop(self):
        self.enabled = False
        if self.timer and self.timer.isAlive():
            self.timer.cancel()
        if self.adb is not None:
            self.adb.terminate()
            self.adb = None

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

        count = CountingThread()
        count.start()

        timeStamp = time.time()
        if duration:
            self.timer = threading.Timer(duration, self.stop)
            self.timer.start()

        if self.adb is None:
            self.adb = Popen(["adb", "logcat", "-v", "threadtime", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Collect DroidBox logs
        self.is_counting_logs = True
        self.lastScreenshot = 0
        first_log_time = None

        from droidbot.adapter.process_monitor import ProcessMonitor
        state_monitor = ProcessMonitor()
        state_monitor.start()

        while self.enabled:
            try:
                if self.output_dir and (time.time() - self.lastScreenshot) >=5:
                    # Take screenshots every 5 seconds.
                    os.system("adb shell screencap -p | sed 's/\r$//' > %s" % os.path.join(self.output_dir, "screen") \
                              + "_$(date +%Y-%m-%d_%H%M%S).png")
                    self.lastScreenshot = time.time()

                logcatInput = self.adb.stdout.readline()
                if not logcatInput:
                    raise LostADBException("We have lost the connection with ADB.")

                from droidbot import utils
                log_data = utils.parse_log(logcatInput)

                if log_data is None or log_data['tag'] != "DroidBox":
                    continue

                log_time = log_data['datetime']
                if first_log_time is None:
                    first_log_time = log_time
                log_delta_seconds = (log_time - first_log_time).total_seconds()
                log_content = json.loads(decode(log_data['content']))

                # DroidBox style report
                try:
                    # dirty workaround: filter out the logs produced by DroidBot
                    # self.filter_noises(log_content)

                    # DexClassLoader
                    if log_content.has_key('DexClassLoader'):
                        log_content['DexClassLoader']['type'] = 'dexload'
                        self.dexclass[log_delta_seconds] = log_content['DexClassLoader']
                        count.increaseCount()

                    # service started
                    if log_content.has_key('ServiceStart'):
                        log_content['ServiceStart']['type'] = 'service'
                        self.servicestart[log_delta_seconds] = log_content['ServiceStart']
                        count.increaseCount()

                    # received data from net
                    if log_content.has_key('RecvNet'):
                        host = log_content['RecvNet']['srchost']
                        port = log_content['RecvNet']['srcport']

                        self.recvnet[log_delta_seconds] = recvdata = {'type': 'net read', 'host': host,
                                                                            'port': port,
                                                                            'data': log_content['RecvNet']['data']}
                        count.increaseCount()

                    # fdaccess
                    if log_content.has_key('FdAccess'):
                        self.accessedfiles[log_content['FdAccess']['id']] = hexToStr(log_content['FdAccess']['path'])

                    # file read or write
                    if log_content.has_key('FileRW'):
                        log_content['FileRW']['path'] = self.accessedfiles[log_content['FileRW']['id']]
                        if log_content['FileRW']['operation'] == 'write':
                            log_content['FileRW']['type'] = 'file write'
                        else:
                            log_content['FileRW']['type'] = 'file read'

                        self.fdaccess[log_delta_seconds] = log_content['FileRW']
                        count.increaseCount()

                    # opened network connection log
                    if log_content.has_key('OpenNet'):
                        self.opennet[log_delta_seconds] = log_content['OpenNet']
                        count.increaseCount()

                    # closed socket
                    if log_content.has_key('CloseNet'):
                        self.closenet[log_delta_seconds] = log_content['CloseNet']
                        count.increaseCount()

                    # outgoing network activity log
                    if log_content.has_key('SendNet'):
                        log_content['SendNet']['type'] = 'net write'
                        self.sendnet[log_delta_seconds] = log_content['SendNet']

                        count.increaseCount()

                    # data leak log
                    if log_content.has_key('DataLeak'):
                        my_time = log_delta_seconds
                        log_content['DataLeak']['type'] = 'leak'
                        log_content['DataLeak']['tag'] = getTags(int(log_content['DataLeak']['tag'], 16))
                        self.dataleaks[my_time] = log_content['DataLeak']
                        count.increaseCount()

                        if log_content['DataLeak']['sink'] == 'Network':
                            log_content['DataLeak']['type'] = 'net write'
                            self.sendnet[my_time] = log_content['DataLeak']
                            count.increaseCount()

                        elif log_content['DataLeak']['sink'] == 'File':
                            log_content['DataLeak']['path'] = self.accessedfiles[log_content['DataLeak']['id']]
                            if log_content['DataLeak']['operation'] == 'write':
                                log_content['DataLeak']['type'] = 'file write'
                            else:
                                log_content['DataLeak']['type'] = 'file read'

                            self.fdaccess[my_time] = log_content['DataLeak']
                            count.increaseCount()

                        elif log_content['DataLeak']['sink'] == 'SMS':
                            log_content['DataLeak']['type'] = 'sms'
                            self.sendsms[my_time] = log_content['DataLeak']
                            count.increaseCount()

                    # sent sms log
                    if log_content.has_key('SendSMS'):
                        log_content['SendSMS']['type'] = 'sms'
                        self.sendsms[log_delta_seconds] = log_content['SendSMS']
                        count.increaseCount()

                    # phone call log
                    if log_content.has_key('PhoneCall'):
                        log_content['PhoneCall']['type'] = 'call'
                        self.phonecalls[log_delta_seconds] = log_content['PhoneCall']
                        count.increaseCount()

                    # crypto api usage log
                    if log_content.has_key('CryptoUsage'):
                        log_content['CryptoUsage']['type'] = 'crypto'
                        self.cryptousage[log_delta_seconds] = log_content['CryptoUsage']
                        count.increaseCount()
                except ValueError:
                    pass
            except KeyboardInterrupt:
                break
            except LostADBException:
                break
            except Exception as e:
                print(e.message)
                continue

        self.is_counting_logs = False
        count.stopCounting()
        count.join()
        # Kill ADB, otherwise it will never terminate
        self.stop()
        self.adb = None

        print json.dumps(self.get_output())
        if self.output_dir is None:
            return
        with open(os.path.join(self.output_dir, "analysis.json"),"w") as jsonfile:
            jsonfile.write(json.dumps(self.get_output(),sort_keys=True, indent=4))

    def get_output(self):
        # Done? Store the objects in a dictionary, transform it in a dict object and return it
        output = dict()

        # Sort the items by their key
        output["dexclass"] = self.dexclass
        output["servicestart"] = self.servicestart

        output["recvnet"] = self.recvnet
        output["opennet"] = self.opennet
        output["sendnet"] = self.sendnet
        output["closenet"] = self.closenet

        output["accessedfiles"] = self.accessedfiles
        output["dataleaks"] = self.dataleaks

        output["fdaccess"] = self.fdaccess
        output["sendsms"] = self.sendsms
        output["phonecalls"] = self.phonecalls
        output["cryptousage"] = self.cryptousage

        output["recvsaction"] = self.application.getRecvsaction()
        output["enfperm"] = self.application.getEnfperm()

        output["hashes"] = self.apk_hashes
        output["apkName"] = self.apk_name
        return output

    def get_counts(self):
        output = dict()

        # Sort the items by their key
        output["dexclass"] = len(self.dexclass)
        output["servicestart"] = len(self.servicestart)

        output["recvnet"] = len(self.recvnet)
        output["opennet"] = len(self.opennet)
        output["sendnet"] = len(self.sendnet)
        output["closenet"] = len(self.closenet)

        output["dataleaks"] = len(self.dataleaks)

        output["fdaccess"] = len(self.fdaccess)
        output["sendsms"] = len(self.sendsms)
        output["phonecalls"] = len(self.phonecalls)
        output["cryptousage"] = len(self.cryptousage)

        output["sum"] = sum(output.values())

        return output

    def filter_noises(self, log):
        """
        filter use less noises from log
        :param log: log of Droidbox in dict format
        :return: boolean
        """
        if isinstance(log, dict):
            # DexClassLoader
            if 'DexClassLoader' in log.keys():
                if log['DexClassLoader']['path'] in DEXCLASSLOADER_EXCLUDED:
                    log.pop('DexClassLoader')

            # fdaccess
            if 'FdAccess' in log.keys():
                for excluded_prefix in FDACCESS_EXCLUDED_PREFIX:
                    if hexToStr(log['FdAccess']['path']).startswith(excluded_prefix):
                        log.pop('FdAccess')
                        break

            # file read or write
            if 'FileRW' in log.keys():
                if log['FileRW']['id'] not in self.accessedfiles.keys():
                    log.pop('FileRW')

        return log


DEXCLASSLOADER_EXCLUDED = [
    "/system/framework/monkey.jar",
    "/system/framework/input.jar",
    "/system/framework/am.jar",
]


FDACCESS_EXCLUDED_PREFIX = [
    "pipe:",
    "socket:",
    "/dev/input/event",
]


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
            sys.stdout.write("     \033[132m[%s] Collected %s sandbox logs\033[1m   (Ctrl-C to view logs)\r" % (
                sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1
            if self.stop:
                sys.stdout.write(
                    "   \033[132m[%s] Collected %s sandbox logs\033[1m%s\r" % ('*', str(self.logs), ' ' * 25))
                sys.stdout.flush()
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

            if (error == False):
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


def main():
    argv = sys.argv
    if len(argv) < 2 or len(argv) > 3:
        print("Usage: droidbox_compatible.py filename.apk <duration in seconds>")
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