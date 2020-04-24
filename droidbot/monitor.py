import frida
import sys
import time
import logging
#import analysis
import subprocess
import os, threading

class Monitor(object):
    """
        this class monitor the sensitive api
        """
    def __init__(self):
        self.packageName = None
        self.device = None
        self.sensitive_api = list()
        self.interested_api = list()
        self.method_stack = list()
        self.attached = False
        self.pid = None
        self.logger = logging.getLogger("APIMonitor")
        self.session = None
        self.serial = None
        self.first_trigger = None
        self.first_trigger_time = 0
        self.trigger_number = 0

    def set_up(self):
        self._setLogPath()
        if self.serial is not None:
            self._start_server()
        else:
            self.logger.error("Device not found")
            return
        if self.packageName is not None:
            self._attach(self.packageName)
            self._load_script(self.session, self.pid)
        else:
            self.logger.error("Package not found")
        return

    def _setLogPath(self):
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(message)s",
                            datefmt='%Y-%m-%d %H:%M',
                            #filename=path,
                            filemode="w")

    def _build_monitor_script(self, dir, topdown=True):
        script = ""
        for root, dirs, files in os.walk(dir, topdown):
            for name in files:
                script += open(os.path.join(root, name)).read()
        return script


    def _on_message(self, message):
        if message['type'] == 'send':
            msg = message['payload']
            if msg[0] == "SENSITIVE":
                if self.first_trigger is None:
                    self.first_trigger_time = time.clock - self.start_time
                    self.first_trigger = True
                self.sensitive_api.append(msg[1])
                self.trigger_number += 1
            else:
                self.interested_api.append(msg[1])
            self.method_stack.append(msg[2])
            # logging.info(message['payload'])
        elif message['type'] == 'error':
            logging.info(message['stack'])

    def _start_server(self):
        task = threading.Thread(target=self._startServer)
        task.start()

    def _startServer(self):
        cmd = "./droidbot/resources/start.sh"
        ret = subprocess.call(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if (ret == 1):
            self.logger.error("frida-server start failed !!!")
            sys.exit(1)

    def _attach(self, packageName):
        try:
            self.device = frida.get_usb_device()
            self.pid = self.device.spawn([packageName])
            self.session = self.device.attach(self.pid)
        except Exception as e:
            self.logger.error("[ERROR]: %s" % str(e))
            self.logger.info("waiting for process")
            # self.notify()
            return None
        self.attached = True
        self.logger.info("successfully attached to app")
        return

    def _detach(self, session):
        session.detach()
        self.attached = False

    def _load_script(self, session, pid):
        if self.attached:
            script_dir = os.path.join(".", "droidbot", "resources", "scripts")
            script_content = self._build_monitor_script(script_dir)
            script = session.create_script(script_content)
            script.on("message", self._on_message)
            script.load()
            self.device.resume(pid)
            self.start_time = time.clock()

    def _getPid(self):
        cmd = "adb shell ps | grep " + self.packageName
        result = os.popen(cmd)
        if result is not None:
            return self.pid
        else:
            cmd = "frida-ps -U"
            temp_pid = None
            result = os.popen(cmd)
            for i in result.readlines():
                if self.packageName != None and self.packageName in i:
                    temp_pid = i.split("  ")[0]
                    break
                else:
                    temp_pid = None
                    print("Process not found")
            self.pid = temp_pid
        #self.notify()
        return self.pid

    def _getDevice(self):
        try:
            self.device = frida.get_usb_device()
        except Exception as e:
            print("Device not found")
            self.device = None
        return

    def _wait_for_devices(self):
        self.logger.info("waiting for device")
        try:
            #subprocess.check_call(["adb", "-s", self.serial, "wait-for-device"])
            while True:
                out = subprocess.check_output(["adb", "-s", self.serial, "shell",
                                               "getprop", "init.svc.bootanim"]).split()[0]
                if str(out) == "b\'stopped\'":
                    break
                time.sleep(3)
        except:
            self.logger.warning("error waiting for device")

    def check_env(self):
        self._getPid()
        self._getDevice()
        if not self.device:
            self._wait_for_devices()
            self.set_up()
            return
        if not self.pid:
            if self.attached is True:
                self._detach(self.session)
        else:
            if self.attached == False:
                self._attach(self.packageName)
                self._load_script(self.session, self.pid)
            return

    def get_sensitive_api(self):
        temp_state = self.sensitive_api
        self.sensitive_api = list()
        return temp_state

    def get_interested_api(self):
        temp_state = self.interested_api
        self.interested_api = list()
        return temp_state

    def get_method_stack_api(self):
        temp_state = self.method_stack
        self.method_stack = list()
        return temp_state

    def get_first_trigger_time(self):
        return self.first_trigger_time

    def get_trigger_number(self):
        return self.trigger_number

    def stop(self):
        self.detach(self.session)
        print("stop monitor...")
        return