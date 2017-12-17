# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
import logging
import os
import sys
import pkg_resources
import shutil
import xmlrpclib
from threading import Timer
from SimpleXMLRPCServer import SimpleXMLRPCServer

from device import Device
from adapter.droidbot import DroidBotConn
from adapter.qemu import QEMUConn
from app import App
from env_manager import AppEnvManager
from input_manager import InputManager


class DroidMaster(object):
    """
    The main class of droidmaster
    DroidMaster currently supports QEMU instance pool only
    """
    # this is a single instance class
    instance = None

    def __init__(self,
                 app_path=None,
                 device_serial=None,
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
                 qemu_hda=None):
        """
        initiate droidmaster, and
        initiate droidbot's with configurations
        :return:
        """
        logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)
        self.logger = logging.getLogger('DroidMaster')
        DroidMaster.instance = self

        # 1. Save DroidBot Parameters
        self.app_path=app_path
        self.device_serial=device_serial
        self.is_emulator=is_emulator

        self.output_dir=output_dir
        os.makedirs(self.output_dir)

        self.env_policy=env_policy
        self.policy_name=policy_name
        self.random_input=random_input
        self.script_path=script_path
        self.event_count=event_count
        self.event_interval=event_interval
        self.timeout=timeout
        self.keep_app=keep_app
        self.keep_env=keep_env
        self.cv_mode=cv_mode
        self.debug_mode=debug_mode
        self.profiling_method=profiling_method
        self.grant_perm=grant_perm

        # 2. Initiate Device Pool
        # {"adb_target": {"pid": pid, }}
        self.domain = "localhost"

        self.adb_default_port = 4444
        self.qemu_default_port = 5555
        self.rpc_port = 6666

        self.qemu_hda = qemu_hda

        self.device_pool_capacity = 3
        self.device_pool = {}
        self.device_unique_id = 0

        for port_offset in range(self.device_pool_capacity):
            adb_port = self.adb_default_port + port_offset
            adb_target = "%s:%s" % (self.domain, adb_port)

            qemu_port = self.qemu_default_port + port_offset

            self.device_pool[adb_target] = {
                "domain": self.domain,
                "adb_port": adb_port,
                "qemu_port": qemu_port,
                # droidbot is indexed by adb_target
                # qemu is indexed by droidbot
                "droidbot": None,
                "qemu": None,
                "id": None
            }
        self.logger.info(self.device_pool)

        # 2. This Server's Parameter
        self.timer = None
        self.enabled = True

    @staticmethod
    def get_instance():
        if DroidMaster.instance is None:
            print "Error: DroidMaster is not initiated!"
            sys.exit(-1)
        return DroidMaster.instance

    def get_available_devices(self):
        return sorted([self.device_pool[x]
                       for x in self.device_pool
                       if self.device_pool[x]["qemu"] is None])

    def get_running_devices(self):
        return sorted([self.device_pool[x]
                       for x in self.device_pool
                       if self.device_pool[x]["qemu"] is not None])

    def start_device(self, device, hda_path, from_snapshot=False, init_script_path=None):
        # 1. get device ID
        device["id"] = self.device_unique_id
        # 2. new QEMU adapter
        device["qemu"] = QEMUConn(hda_path, device["qemu_port"], device["adb_port"])
        device["qemu"].set_up()
        device["qemu"].connect(from_snapshot)
        # 3. new DroidWorker adapter
        script_path = init_script_path if init_script_path else self.script_path
        device["droidbot"] = DroidBotConn(device["id"],
                                          app_path=self.app_path,
                                          device_serial="%s:%d" % \
                                          (self.domain, device["adb_port"]),
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
                                          master="http://%s:%d/" % \
                                          (self.domain, self.rpc_port))
        device["droidbot"].set_up()
        self.logger.info("Worker: DOMAIN[%s], ADB[%s], QEMU[%d], ID[%d]" % \
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

    def spawn(self, adb_target, init_script_json):
        """
          A worker requests to spawn a new worker
          based on its current state
        """
        device = self.device_pool[adb_target]
        device["qemu"].send_command("stop")
        device["qemu"].send_command("savevm spawn")

        # copy qemu image file
        new_hda_path = "%s.%d" % (device["qemu"].hda_path, \
                                  self.device_unique_id)
        shutil.copyfile(device["qemu"].hda_path, new_hda_path)

        # prepare init script file
        import json
        init_script_path = "%s%s%d.json" % (self.output_dir, os.path.sep,
                                            self.device_unique_id)
        with open(init_script_path, "w") as init_script_file:
            init_script_file.write(init_script_json)

        available_devices = self.get_available_devices()
        if not len(available_devices):
            self.logger.warning("No available device slot")
            return False
        self.start_device(available_devices[0], new_hda_path,
                          from_snapshot=True, init_script_path=init_script_path)

        device["qemu"].send_command("delvm test1")
        device["qemu"].send_command("cont")
        self.logger.info("Spawning worker")
        return True

    def start_worker(self):
        """
          Start the first worker, used by DroidMaster itself
        """
        # copy qemu image file
        new_hda_path = "%s.%d" % (self.qemu_hda, \
                                  self.device_unique_id)
        shutil.copyfile(self.qemu_hda, new_hda_path)

        available_devices = self.get_available_devices()
        if not len(available_devices):
            self.logger.warning("No available device slot")
            return False
        self.start_device(available_devices[0], new_hda_path)
        return True

    def start_daemon(self):
        self.server = SimpleXMLRPCServer((self.domain, self.rpc_port))
        print "Listening on port %s..." % self.rpc_port
        self.server.register_function(self.spawn, "spawn")
        self.server.register_function(self.start_worker, "start_worker")
        self.server.serve_forever()

    def stop_daemon(self):
        print "Shutting down DroidMaster server..."
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
                self.timer = Timer(self.timeout, self.stop)
                self.timer.start()

            if not self.enabled:
                return

            # enable server listening workers
            import time
            import threading
            self.server_thread = threading.Thread(target=self.start_daemon)
            self.server_thread.daemon = True
            self.server_thread.start()
            time.sleep(1) # wait server to start

            # create first droidbot instance
            proxy = xmlrpclib.ServerProxy("http://%s:%d/" % (self.domain, self.rpc_port))
            proxy.start_worker()

            while len(self.get_running_devices()):
                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt.")
            pass
        except Exception as e:
            self.logger.warning("Something went wrong: " + e.message)
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
