import logging
import subprocess
from utils import Timeout


class MonkeyRunnerException(Exception):
    """
    Exception in monkeyrunner connection
    """
    pass


class MonkeyRunner(object):
    """
    interface of monkey runner connection
    we DO NOT use monkeyrunner because it conflicts with adb
    http://developer.android.com/tools/help/monkeyrunner_concepts.html
    """
    def __init__(self, device):
        """
        initiate a monkeyrunner shell
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('MonkeyRunner')
        self.console = subprocess.Popen('monkeyrunner', stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.running = True
        self.run_cmd('from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice')
        self.run_cmd('device=MonkeyRunner.waitForConnection(5,\'%s\')' % device.serial)
        if self.check_connectivity():
            self.logger.debug("monkeyrunner successfully initiated, the device is %s" % device.serial)
        else:
            raise MonkeyRunnerException()

    def get_output(self, timeout=0):
        output = ""
        with Timeout(timeout):
            while True:
                line = self.console.stdout.readline()
                if line == '>>> \n':
                    break
                if line.startswith('>>>'):
                    continue
                output += line
        return output

    def run_cmd(self, args):
        """
        run a command via monkeyrunner
        :param args: arguments to be executed in monkeyrunner console
        :return:
        """
        if isinstance(args, list):
            cmd_line = " ".join(args)
        else:
            cmd_line = args
        self.logger.debug('command:')
        self.logger.debug(cmd_line)
        cmd_line += '\n\n'
        self.console.stdin.write(cmd_line)
        self.console.stdin.flush()
        r=self.get_output()
        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def check_connectivity(self):
        """
        check if console is connected
        :return: True for connected
        """
        try:
            self.run_cmd("r=device.getProperty(\'clock.millis\')")
            out = self.run_cmd("print r")
            segs = out.split('\n')
            if int(segs[0]) <= 0:
                return False
        except:
            return False
        return True

    def disconnect(self):
        """
        disconnect monkeyrunner
        :return:
        """
        self.running = False
        self.console.terminate()
        self.logger.debug("disconnected")
