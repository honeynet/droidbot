# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
import logging
import os
import shutil
import subprocess
import sys
import time
import threading

from xmlrpc.client import ServerProxy
if sys.version.startswith("3"):
    from xmlrpc.server import SimpleXMLRPCServer
    from xmlrpc.server import SimpleXMLRPCRequestHandler
else:
    from SimpleXMLRPCServer import SimpleXMLRPCServer
    from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

from .device import Device
from .app import App

from .adapter.droidbot import DroidBotConn
from .adapter.qemu import QEMUConn

class RPCHandler(SimpleXMLRPCRequestHandler):
    def _dispatch(self, method, params):
        try:
            return self.server.funcs[method](*params)
        except:
            import traceback
            traceback.print_exc()
            raise

class DroidMaster(object):
    """
    The main class of droidmaster
    DroidMaster currently supports QEMU instance pool only
    """
    # this is a single instance class
    instance = None
    POLL_INTERVAL = 1

    def __init__(self,
                 app_path=None,
                 is_emulator=False,
                 output_dir=None,
                 env_policy=None,
                 policy_name=None,
                 random_input=False,
                 script_path=None,
                 event_count=None,
                 event_interval=None,
                 timeout=None,
                 keep_app=None,
                 keep_env=False,
                 cv_mode=False,
                 debug_mode=False,
                 profiling_method=None,
                 grant_perm=False,
                 enable_accessibility_hard=False,
                 qemu_hda=None,
                 qemu_no_graphic=False,
                 humanoid=None,
                 ignore_ad=False,
                 replay_output=None):
        """
        initiate droidmaster, and
        initiate droidbot's with configurations
        :return:
        """
        logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)
        self.logger = logging.getLogger('DroidMaster')
        DroidMaster.instance = self

        # 1. Save DroidBot Parameters
        self.app_path = app_path
        self.is_emulator = is_emulator

        self.output_dir = output_dir
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        self.env_policy = env_policy
        self.policy_name = policy_name
        self.random_input = random_input
        self.script_path = script_path
        self.event_count = event_count
        self.event_interval = event_interval
        self.timeout = timeout
        self.keep_app = keep_app
        self.keep_env = keep_env
        self.cv_mode = cv_mode
        self.debug_mode = debug_mode
        self.profiling_method = profiling_method
        self.grant_perm = grant_perm
        self.enable_accessibility_hard = enable_accessibility_hard
        self.humanoid = humanoid
        self.ignore_ad = ignore_ad
        self.replay_output = replay_output

        # 2. Initiate Device Pool
        self.domain = "localhost"
        self.rpc_port = Device(device_serial="").get_random_port()

        self.qemu_hda = qemu_hda
        self.qemu_no_graphic = qemu_no_graphic

        self.device_pool_capacity = 6
        self.device_pool = {}
        self.device_unique_id = 0

        self.app = App(app_path, output_dir=self.output_dir)
        self.qemu_app_hda = "%s_%s" % (self.qemu_hda, self.app.get_package_name())

        for i in range(self.device_pool_capacity):
            adb_port = Device(device_serial="").get_random_port()
            device_serial = "%s:%s" % (self.domain, adb_port)
            qemu_port = Device(device_serial="").get_random_port()
            device = Device(
                device_serial=device_serial,
                is_emulator=self.is_emulator,
                output_dir=self.output_dir,
                cv_mode=self.cv_mode,
                grant_perm=self.grant_perm,
                enable_accessibility_hard=self.enable_accessibility_hard)

            self.device_pool[device_serial] = {
                "domain": self.domain,
                "adb_port": adb_port,
                "qemu_port": qemu_port,
                # droidbot is indexed by device_serial
                # qemu is indexed by droidbot
                "droidbot": None,
                "qemu": None,
                "id": None,
                "device": device
            }
        self.logger.info(self.device_pool)

        # 2. This Server's Parameter
        self.timer = None
        self.enabled = True
        self.successful_spawn_events = set()

    @staticmethod
    def get_instance():
        if DroidMaster.instance is None:
            print("Error: DroidMaster is not initiated!")
            sys.exit(-1)
        return DroidMaster.instance

    def get_available_devices(self):
        return sorted([self.device_pool[x]
                       for x in self.device_pool
                       if self.device_pool[x]["droidbot"] is None and \
                          self.device_pool[x]["qemu"] is None], key=lambda x: x["adb_port"])

    def get_running_devices(self):
        return sorted([self.device_pool[x]
                       for x in self.device_pool
                       if self.device_pool[x]["droidbot"] is not None and \
                          self.device_pool[x]["qemu"] is not None], key=lambda x: x["adb_port"])

    def start_device(self, device, hda, from_snapshot=False, init_script_path=None):
        # 1. get device ID
        device["id"] = self.device_unique_id
        # 2. new QEMU adapter
        device["qemu"] = QEMUConn(hda, device["qemu_port"], device["adb_port"],
                                  self.qemu_no_graphic)
        device["qemu"].set_up()
        device["qemu"].connect(from_snapshot)
        # 3. new DroidWorker adapter
        script_path = init_script_path if init_script_path else self.script_path
        device["droidbot"] = DroidBotConn(device["id"],
                                          app_path=self.app_path,
                                          device_serial=device["device"].serial,
                                          is_emulator=self.is_emulator,
                                          output_dir=self.output_dir,
                                          env_policy=self.env_policy,
                                          policy_name=self.policy_name,
                                          random_input=self.random_input,
                                          script_path=script_path,
                                          event_count=self.event_count,
                                          event_interval=self.event_interval,
                                          timeout=self.timeout,
                                          keep_app=self.keep_app,
                                          keep_env=self.keep_env,
                                          cv_mode=self.cv_mode,
                                          debug_mode=self.debug_mode,
                                          profiling_method=self.profiling_method,
                                          grant_perm=self.grant_perm,
                                          enable_accessibility_hard=self.enable_accessibility_hard,
                                          master="http://%s:%d/" % (self.domain, self.rpc_port),
                                          humanoid=self.humanoid,
                                          ignore_ad=self.ignore_ad,
                                          replay_output=self.replay_output)
        device["droidbot"].set_up()
        self.logger.info("Worker: DOMAIN[%s], ADB[%s], QEMU[%d], ID[%d]" %
                         (device["domain"], device["adb_port"],
                          device["qemu_port"], device["id"]))
        self.device_unique_id += 1

    def stop_device(self, device):
        device["droidbot"].tear_down()
        device["droidbot"].disconnect()
        device["droidbot"] = None
        device["qemu"].disconnect()
        device["qemu"].tear_down()
        device["qemu"] = None

    def qemu_create_img(self, new_hda, back_hda):
        self.logger.info("%s -> %s" % (back_hda, new_hda))
        p = subprocess.Popen(["qemu-img", "create", "-f", "qcow2", new_hda,
                              "-o", "backing_file=%s" % back_hda, "8G"])
        p.wait()

    def spawn(self, device_serial, init_script_json):
        """
          A worker requests to spawn a new worker
          based on its current state
        """
        if init_script_json in self.successful_spawn_events:
            self.logger.warning("Event spawned already")
            return False

        available_devices = self.get_available_devices()
        if not len(available_devices):
            self.logger.warning("No available device slot")
            return False

        calling_device = self.device_pool[device_serial]
        calling_device["qemu"].send_command("stop")
        calling_device["qemu"].send_command("savevm spawn")

        # copy qemu image file (almost RAM image size only)
        new_hda = "%s.%d" % (self.qemu_app_hda, self.device_unique_id)
        shutil.copyfile(calling_device["qemu"].hda, new_hda)

        # prepare init script file
        init_script_path = os.path.join(self.output_dir, "%d.json" % self.device_unique_id)
        with open(init_script_path, "w") as init_script_file:
            init_script_file.write(init_script_json)

        self.start_device(available_devices[0], new_hda,
                          from_snapshot=True, init_script_path=init_script_path)

        calling_device["qemu"].send_command("delvm spawn")
        calling_device["qemu"].send_command("cont")

        self.successful_spawn_events.add(init_script_json)
        self.logger.info("Spawning worker")
        return True

    def start_worker(self):
        """
          Start the first worker (with device 0), used by DroidMaster itself
        """
        available_devices = self.get_available_devices()
        if not len(available_devices):
            self.logger.warning("No available device slot")
            return False

        device = available_devices[0]
        # if app image doesn't exist, create it first
        if not os.path.exists(self.qemu_app_hda):
            self.qemu_create_img(self.qemu_app_hda, self.qemu_hda)
            app_install_qemu = QEMUConn(self.qemu_app_hda,
                                        device["qemu_port"],
                                        device["adb_port"],
                                        self.qemu_no_graphic)
            app_install_qemu.set_up()
            app_install_qemu.connect()
            device["device"].wait_for_device()
            device["device"].install_app(self.app)
            app_install_qemu.disconnect()
            device["device"].shutdown()
            app_install_qemu.tear_down()

        new_hda = "%s.%d" % (self.qemu_app_hda, self.device_unique_id)
        self.qemu_create_img(new_hda, self.qemu_app_hda)

        self.start_device(available_devices[0], new_hda)
        return True

    def stop_worker(self, device_serial):
        self.stop_device(self.device_pool[device_serial])

    def start_daemon(self):
        self.server = SimpleXMLRPCServer((self.domain, self.rpc_port), RPCHandler)
        print("Listening on port %s..." % self.rpc_port)
        self.server.register_function(self.spawn, "spawn")
        self.server.register_function(self.start_worker, "start_worker")
        self.server.register_function(self.stop_worker, "stop_worker")
        self.server.serve_forever()

    def stop_daemon(self):
        print("Shutting down DroidMaster server...")
        self.server.shutdown()
        self.server_thread.join(0)

    def start(self):
        """
        start interacting
        :return:
        """
        if not self.enabled:
            return
        self.logger.info("Starting DroidMaster")
        try:
            if self.timeout > 0:
                self.timer = threading.Timer(self.timeout, self.stop)
                self.timer.start()

            if not self.enabled:
                return

            # enable server listening workers
            self.server_thread = threading.Thread(target=self.start_daemon)
            self.server_thread.daemon = True
            self.server_thread.start()
            time.sleep(1)  # wait server to start

            # create first droidbot instance
            proxy = ServerProxy("http://%s:%d/" % (self.domain, self.rpc_port))
            proxy.start_worker()

            while len(self.get_running_devices()):
                time.sleep(self.POLL_INTERVAL)

        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt.")
            pass
        except Exception:
            import traceback
            traceback.print_exc()
            self.stop()
            sys.exit(-1)

        self.stop()
        self.logger.info("DroidMaster Stopped")

    def stop(self):
        self.enabled = False
        if self.timer and self.timer.isAlive():
            self.timer.cancel()
        # stop listening server
        self.stop_daemon()
        # stop all workers
        running_devices = self.get_running_devices()
        for device in running_devices:
            self.stop_device(device)


class DroidMasterException(Exception):
    pass
