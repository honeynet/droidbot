__author__ = 'yuanchun'
import logging, subprocess

JDB_DEFAULT_HOST_PORT = 7336


class JDBException(Exception):
    """
    Exception in JDB connection
    """
    pass


class JDB(object):
    """
    interface of JDB
    send jdb commands
    """

    def __init__(self, device, app_pid, host_port=JDB_DEFAULT_HOST_PORT):
        """
        initiate a JDB connection
        :param device: instance of Device
        :param app_pid: pid of the app to attach
        :param host_port: the tcp port to use on the host machine
        :return:
        """
        self.logger = logging.getLogger('JDB')
        self.device = device
        self.app_pid = app_pid
        self.host_port = host_port

        # TODO connect to jdb
        device.get_adb().run_cmd("forward tcp:%d jdwp:%d" % (app_pid, host_port))
        self.console = subprocess.Popen(["jdb", "-attach", "localhost:%d" % host_port],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        if self.check_connectivity():
            self.logger.info("jdb successfully initiated, the device is %s" % device.serial)
        else:
            raise JDBException()

    def run_cmd(self, command):
        """
        run a jdb command and return the output
        :return: output of jdb command
        @param command: command to run
        """
        self.logger.debug('command:')
        self.logger.debug(command)
        # TODO send command and get result
        self.console.stdin.write(command + "\n")
        r = self.console.stdout.readall()
        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def check_connectivity(self):
        """
        check if jdb is connected
        :return: True for connected
        """
        r = self.run_cmd("help")
        return False

    def disconnect(self):
        """
        disconnect jdb
        """
        self.logger.info("disconnected")