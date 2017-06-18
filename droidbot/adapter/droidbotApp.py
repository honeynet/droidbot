import logging
import socket
import subprocess
import json

DROIDBOT_APP_REMOTE_ADDR = "tcp:7336"


class DroidBotAppConnException(Exception):
    """
    Exception in telnet connection
    """
    pass


class DroidBotAppConn(object):
    """
    a connection with droidbot app.
    """
    def __init__(self, device=None):
        """
        initiate a emulator console via telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('DroidBotAppConn')
        self.host = "localhost"
        self.port = 7336
        self.device = device

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = True

        try:
            # forward host port to remote port
            serial_cmd = "" if device is None else "-s " + device.serial
            forward_cmd = "adb %s forward tcp:%d %s" % (serial_cmd, self.port, DROIDBOT_APP_REMOTE_ADDR)
            subprocess.check_call(forward_cmd.split())
            self.sock.connect((self.host, self.port))
            import threading
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.start()
        except socket.error, ex:
            self.connected = False
            raise DroidBotAppConnException()

    def listen_messages(self):
        self.logger.debug("start listening messages")
        CHUNK_SIZE = 1024
        read_message_bytes = 0
        message_len = 0
        message = ""
        while self.connected:
            chunk = self.sock.recv(CHUNK_SIZE)
            # print chunk
            if not chunk:
                continue
            chunk_len = len(chunk)
            cursor = 0
            while cursor < chunk_len:
                b = ord(chunk[cursor])
                if read_message_bytes == 0:
                    if b != 0xff:
                        continue
                elif read_message_bytes == 1:
                    if b != 0x00:
                        continue
                elif read_message_bytes < 6:
                    message_len += b << ((5 - read_message_bytes) * 8)
                    # if read_message_bytes == 5:
                    #     print "received a message with a length of %d" % message_len
                else:
                    if chunk_len - cursor >= message_len:
                        message += chunk[cursor:(cursor + message_len)]
                        # print "received a message:"
                        # print message
                        self.handle_message(message)
                        cursor += message_len
                        message_len = 0
                        read_message_bytes = 0
                        message = ""
                        continue
                    else:
                        message += chunk[cursor:]
                        message_len -= (chunk_len - cursor)
                        read_message_bytes += (chunk_len - cursor)
                        break
                read_message_bytes += 1
                cursor += 1

    def handle_message(self, message):
        tag_index = message.find(" >>> ")
        if tag_index != -1:
            tag = message[:tag_index]
            print "received a message with a tag: " + tag
            body = json.loads(message[(tag_index + 5):])
            print body.keys()

    def run_cmd(self, args):
        """
        run a command in emulator console
        :param args: arguments to be executed in telnet console
        :return:
        """
        if isinstance(args, list):
            cmd_line = " ".join(args)
        elif isinstance(args, str):
            cmd_line = args
        else:
            self.logger.warning("unsupported command format:" + args)
            return

        self.logger.debug('command:')
        self.logger.debug(cmd_line)

        result = None
        # TODO implement this

        self.logger.debug('return:')
        self.logger.debug(result)
        return result

    def check_connectivity(self):
        """
        check if droidbot app is connected
        :return: True for connected
        """
        return self.connected

    def disconnect(self):
        """
        disconnect telnet
        """
        self.sock.close()
        self.connected = False
        self.logger.debug("disconnected")

if __name__ == "__main__":
    droidbot_app_conn = DroidBotAppConn()
