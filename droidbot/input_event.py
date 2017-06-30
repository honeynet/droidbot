import json
import os
import random
import time

import utils
from intent import Intent

POSSIBLE_KEYS = [
    "BACK",
    "MENU",
    "HOME"
]

KEY_KeyEvent = "key"
KEY_TouchEvent = "touch"
KEY_LongTouchEvent = "long_touch"
KEY_DragEvent = "drag"
KEY_SwipeEvent = "swipe"
KEY_TextInputEvent = "text_input"
KEY_IntentEvent = "intent"


class InputEvent(object):
    """
    The base class of all events
    """

    def to_dict(self):
        return self.__dict__

    def to_json(self):
        return json.dumps(self.to_dict())

    def __str__(self):
        return self.to_dict().__str__()

    def send(self, device):
        """
        send this event to device
        :param device: Device
        :return:
        """
        raise NotImplementedError

    @staticmethod
    def get_random_instance(device, app):
        """
        get a random instance of event
        :param device: Device
        :param app: App
        """
        raise NotImplementedError

    @staticmethod
    def from_dict(event_dict):
        if not isinstance(event_dict, dict):
            return None
        if 'event_type' not in event_dict:
            return None
        event_type = event_dict['event_type']
        if event_type == KEY_KeyEvent:
            return KeyEvent(event_dict=event_dict)
        elif event_type == KEY_TouchEvent:
            return TouchEvent(event_dict=event_dict)
        elif event_type == KEY_LongTouchEvent:
            return LongTouchEvent(event_dict=event_dict)
        elif event_type == KEY_DragEvent:
            return DragEvent(event_dict=event_dict)
        elif event_type == KEY_SwipeEvent:
            return SwipeEvent(event_dict=event_dict)
        elif event_type == KEY_TextInputEvent:
            return TextInputEvent(event_dict=event_dict)
        elif event_type == KEY_IntentEvent:
            return IntentEvent(event_dict=event_dict)


class EventLog(object):
    """
    save an event to local file system
    """

    def __init__(self, device, app, event, profiling_method=None, tag=None):
        self.device = device
        self.app = app
        self.event = event
        if tag is None:
            from datetime import datetime
            tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.tag = tag

        self.trace_remote_file = "/data/local/tmp/event.trace"
        self.is_profiling = False
        self.profiling_pid = -1
        self.sampling = None
        # sampling feature was added in Android 5.0 (API level 21)
        if profiling_method is not None and \
           str(profiling_method) != "full" and \
           self.device.get_sdk_version() >= 21:
            self.sampling = int(profiling_method)

    def to_dict(self):
        return {
            "tag": self.tag,
            "event": self.event.to_dict()
        }

    def save2dir(self, output_dir=None):
        if output_dir is None:
            if self.device.output_dir is None:
                return
            else:
                output_dir = os.path.join(self.device.output_dir, "events")
        try:
            if not os.path.exists(output_dir):
                os.mkdir(output_dir)
            event_json_file_path = "%s/event_%s.json" % (output_dir, self.tag)
            event_json_file = open(event_json_file_path, "w")
            json.dump(self.to_dict(), event_json_file, indent=2)
            event_json_file.close()
        except Exception as e:
            self.device.logger.warning("Saving event to dir failed: " + e.message)

    def is_start_event(self):
        if isinstance(self.event, IntentEvent):
            intent_cmd = self.event.intent
            if "start" in intent_cmd and self.app.get_package_name() in intent_cmd:
                return True
        return False

    def start_profiling(self):
        """
        start profiling the current event
        @return:
        """
        if self.is_profiling:
            return
        pid = self.device.get_app_pid(self.app)
        if pid is None:
            if self.is_start_event():
                start_intent = self.app.get_start_with_profiling_intent(self.trace_remote_file, self.sampling)
                self.event.intent = start_intent.get_cmd()
                self.is_profiling = True
            return
        if self.sampling is not None:
            self.device.adb.shell(
                ["am", "profile", "start", "--sampling", str(self.sampling), str(pid), self.trace_remote_file])
        else:
            self.device.adb.shell(["am", "profile", "start", str(pid), self.trace_remote_file])
        self.is_profiling = True
        self.profiling_pid = pid

    def stop_profiling(self, output_dir=None):
        if not self.is_profiling:
            return
        try:
            if self.profiling_pid == -1:
                pid = self.device.get_app_pid(self.app)
                if pid is None:
                    return
                self.profiling_pid = pid

            self.device.adb.shell(["am", "profile", "stop", str(self.profiling_pid)])
            if self.sampling is None:
                time.sleep(3)  # guess this time can vary between machines

            if output_dir is None:
                if self.device.output_dir is None:
                    return
                else:
                    output_dir = os.path.join(self.device.output_dir, "events")
            if not os.path.exists(output_dir):
                os.mkdir(output_dir)
            event_trace_local_path = "%s/event_trace_%s.trace" % (output_dir, self.tag)
            self.device.pull_file(self.trace_remote_file, event_trace_local_path)

        except Exception as e:
            self.device.logger.warning("profiling event failed: " + e.message)


class KeyEvent(InputEvent):
    """
    a key pressing event
    """

    def __init__(self, name=None, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_KeyEvent
        self.name = name

    @staticmethod
    def get_random_instance(device, app):
        key_name = random.choice(POSSIBLE_KEYS)
        return KeyEvent(key_name)

    def send(self, device):
        device.key_press(self.name)
        return True


class UIEvent(InputEvent):
    """
    This class describes a UI event of app, such as touch, click, etc
    """

    def send(self, device):
        raise NotImplementedError

    @staticmethod
    def get_random_instance(device, app):
        if not device.is_foreground(app):
            # if current app is in background, bring it to foreground
            component = app.get_package_name()
            if app.get_main_activity():
                component += "/%s" % app.get_main_activity()
            return IntentEvent(Intent(suffix=component))

        else:
            choices = {
                TouchEvent: 6,
                LongTouchEvent: 2,
                DragEvent: 2
            }
            event_type = utils.weighted_choice(choices)
            return event_type.get_random_instance(device, app)


class TouchEvent(UIEvent):
    """
    a touch on screen
    """

    def __init__(self, x=None, y=None, view=None, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_TouchEvent
        self.x = x
        self.y = y
        self.view = view

    @staticmethod
    def get_random_instance(device, app):
        x = random.uniform(0, device.get_width())
        y = random.uniform(0, device.get_height())
        return TouchEvent(x, y)

    def send(self, device):
        device.view_long_touch(self.x, self.y, duration=300)
        return True


class LongTouchEvent(UIEvent):
    """
    a long touch on screen
    """

    def __init__(self, x=None, y=None, view=None, duration=2000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_LongTouchEvent
        self.x = x
        self.y = y
        self.view = view
        self.duration = duration

    @staticmethod
    def get_random_instance(device, app):
        x = random.uniform(0, device.get_width())
        y = random.uniform(0, device.get_height())
        return LongTouchEvent(x, y)

    def send(self, device):
        device.view_long_touch(self.x, self.y, self.duration)
        return True


class DragEvent(UIEvent):
    """
    a drag gesture on screen
    """

    def __init__(self,
                 start_x=None, start_y=None, start_view=None,
                 end_x=None, end_y=None, end_view=None,
                 duration=1000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_DragEvent

        self.start_x = start_x
        self.start_y = start_y
        self.start_view = start_view

        self.end_x = end_x
        self.end_y = end_y
        self.end_view = end_view

        self.duration = duration

    @staticmethod
    def get_random_instance(device, app):
        start_x = random.uniform(0, device.get_width())
        start_y = random.uniform(0, device.get_height())
        end_x = random.uniform(0, device.get_width())
        end_y = random.uniform(0, device.get_height())
        return DragEvent(start_x=start_x, start_y=start_y,
                         end_x=end_x, end_y=end_y)

    def send(self, device):
        device.view_drag((self.start_x, self.start_y),
                         (self.end_x, self.end_y),
                         self.duration)
        return True


class SwipeEvent(UIEvent):
    """
    swipe gesture
    """

    def __init__(self, x=None, y=None, view=None, direction="UP", event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_SwipeEvent
        self.x = x
        self.y = y
        self.view = view
        self.direction = direction

    @staticmethod
    def get_random_instance(device, app):
        x = random.uniform(0, device.get_width())
        y = random.uniform(0, device.get_height())
        direction = random.choice(["UP", "DOWN", "LEFT", "RIGHT"])
        return SwipeEvent(x, y, direction)

    def send(self, device):
        end_x = self.x
        end_y = self.y
        duration = 200

        if self.direction == "UP":
            end_y = 0
        elif self.direction == "DOWN":
            end_y = device.get_height()
        elif self.direction == "LEFT":
            end_x = 0
        elif self.direction == "RIGHT":
            end_x = device.get_width()

        device.view_drag((self.x, self.y), (end_x, end_y), duration)
        return True


class TextInputEvent(UIEvent):
    """
    input text to target UI
    """

    @staticmethod
    def get_random_instance(device, app):
        pass

    def __init__(self, x=None, y=None, view=None, text=None, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_TextInputEvent
        self.x = x
        self.y = y
        self.view = view
        self.text = text

    def send(self, device):
        touch_event = TouchEvent(x=self.x, y=self.y)
        touch_event.send(device)
        escaped = self.text.replace('%s', '\\%s')
        encoded = escaped.replace(' ', '%s')
        device.adb.type(encoded)
        return True


class IntentEvent(InputEvent):
    """
    An event describing an intent
    """

    def __init__(self, intent=None, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_IntentEvent
        self.intent = intent.get_cmd() if isinstance(intent, Intent) else ""

    @staticmethod
    def get_random_instance(device, app):
        pass

    def send(self, device):
        device.send_intent(intent=self.intent)
        return True


EVENT_TYPES = {
    KEY_KeyEvent: KeyEvent,
    KEY_TouchEvent: TouchEvent,
    KEY_LongTouchEvent: LongTouchEvent,
    KEY_DragEvent: DragEvent,
    KEY_SwipeEvent: SwipeEvent,
    KEY_IntentEvent: IntentEvent,
}
