# This file is responsible for generating events to interact with app at runtime
# The events includes:
#     1. UI events. click, touch, etc
#     2, intent events. broadcast events of App installed, new SMS, etc.
# The intention of these events is to exploit more mal-behaviours of app as soon as possible
__author__ = 'liyc'
import logging
import json
import time
import os
import random
import subprocess
from threading import Timer
from types import Intent

EVENT_POLICIES = [
    "none",
    "monkey",
    "random",
    "static",
    "dynamic",
    "file"
]

POSSIBLE_KEYS = [
    "BACK",
    "MENU",
    "HOME",
    "VOLUME_UP"
    "VOLUME_DOWN"
]

POSSIBLE_ACTIONS = '''
android.intent.action.AIRPLANE_MODE_CHANGED
android.intent.action.ALL_APPS
android.intent.action.ANSWER
android.intent.action.APPLICATION_RESTRICTIONS_CHANGED
android.intent.action.APP_ERROR
android.intent.action.ASSIST
android.intent.action.ATTACH_DATA
android.intent.action.BATTERY_CHANGED
android.intent.action.BATTERY_LOW
android.intent.action.BATTERY_OKAY
android.intent.action.BOOT_COMPLETED
android.intent.action.BUG_REPORT
android.intent.action.CALL
android.intent.action.CALL_BUTTON
android.intent.action.CAMERA_BUTTON
android.intent.action.CHOOSER
android.intent.action.CLOSE_SYSTEM_DIALOGS
android.intent.action.CONFIGURATION_CHANGED
android.intent.action.CREATE_DOCUMENT
android.intent.action.CREATE_SHORTCUT
android.intent.action.DATE_CHANGED
android.intent.action.DEFAULT
android.intent.action.DELETE
android.intent.action.DEVICE_STORAGE_LOW
android.intent.action.DEVICE_STORAGE_OK
android.intent.action.DIAL
android.intent.action.DOCK_EVENT
android.intent.action.DREAMING_STARTED
android.intent.action.DREAMING_STOPPED
android.intent.action.EDIT
android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE
android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE
android.intent.action.FACTORY_TEST
android.intent.action.GET_CONTENT
android.intent.action.GET_RESTRICTION_ENTRIES
android.intent.action.GTALK_SERVICE_CONNECTED
android.intent.action.GTALK_SERVICE_DISCONNECTED
android.intent.action.HEADSET_PLUG
android.intent.action.INPUT_METHOD_CHANGED
android.intent.action.INSERT
android.intent.action.INSERT_OR_EDIT
android.intent.action.INSTALL_PACKAGE
android.intent.action.LOCALE_CHANGED
android.intent.action.MAIN
android.intent.action.MANAGED_PROFILE_ADDED
android.intent.action.MANAGED_PROFILE_REMOVED
android.intent.action.MANAGE_NETWORK_USAGE
android.intent.action.MANAGE_PACKAGE_STORAGE
android.intent.action.MEDIA_BAD_REMOVAL
android.intent.action.MEDIA_BUTTON
android.intent.action.MEDIA_CHECKING
android.intent.action.MEDIA_EJECT
android.intent.action.MEDIA_MOUNTED
android.intent.action.MEDIA_NOFS
android.intent.action.MEDIA_REMOVED
android.intent.action.MEDIA_SCANNER_FINISHED
android.intent.action.MEDIA_SCANNER_SCAN_FILE
android.intent.action.MEDIA_SCANNER_STARTED
android.intent.action.MEDIA_SHARED
android.intent.action.MEDIA_UNMOUNTABLE
android.intent.action.MEDIA_UNMOUNTED
android.intent.action.MY_PACKAGE_REPLACED
android.intent.action.NEW_OUTGOING_CALL
android.intent.action.OPEN_DOCUMENT
android.intent.action.OPEN_DOCUMENT_TREE
android.intent.action.PACKAGE_ADDED
android.intent.action.PACKAGE_CHANGED
android.intent.action.PACKAGE_DATA_CLEARED
android.intent.action.PACKAGE_FIRST_LAUNCH
android.intent.action.PACKAGE_FULLY_REMOVED
android.intent.action.PACKAGE_INSTALL
android.intent.action.PACKAGE_NEEDS_VERIFICATION
android.intent.action.PACKAGE_REMOVED
android.intent.action.PACKAGE_REPLACED
android.intent.action.PACKAGE_RESTARTED
android.intent.action.PACKAGE_VERIFIED
android.intent.action.PASTE
android.intent.action.PICK
android.intent.action.PICK_ACTIVITY
android.intent.action.POWER_CONNECTED
android.intent.action.POWER_DISCONNECTED
android.intent.action.POWER_USAGE_SUMMARY
android.intent.action.PROVIDER_CHANGED
android.intent.action.QUICK_CLOCK
android.intent.action.REBOOT
android.intent.action.RUN
android.intent.action.SCREEN_OFF
android.intent.action.SCREEN_ON
android.intent.action.SEARCH
android.intent.action.SEARCH_LONG_PRESS
android.intent.action.SEND
android.intent.action.SENDTO
android.intent.action.SEND_MULTIPLE
android.intent.action.SET_WALLPAPER
android.intent.action.SHUTDOWN
android.intent.action.SYNC
android.intent.action.SYSTEM_TUTORIAL
android.intent.action.TIMEZONE_CHANGED
android.intent.action.TIME_CHANGED
android.intent.action.TIME_TICK
android.intent.action.UID_REMOVED
android.intent.action.UMS_CONNECTED
android.intent.action.UMS_DISCONNECTED
android.intent.action.UNINSTALL_PACKAGE
android.intent.action.USER_BACKGROUND
android.intent.action.USER_FOREGROUND
android.intent.action.USER_INITIALIZE
android.intent.action.USER_PRESENT
android.intent.action.VIEW
android.intent.action.VOICE_COMMAND
android.intent.action.WALLPAPER_CHANGED
android.intent.action.WEB_SEARCH
'''.splitlines()


def weighted_choice(choices):
    total = sum(choices[c] for c in choices.keys())
    r = random.uniform(0, total)
    upto = 0
    for c in choices.keys():
        if upto + choices[c] > r:
            return c
        upto += choices[c]


class UnknownEventException(Exception):
    pass


class AppEvent(object):
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


class KeyEvent(AppEvent):
    """
    a key pressing event
    """

    def __init__(self, name, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'key'
        self.name = name

    @staticmethod
    def get_random_instance(device, app):
        key_name = random.choice(POSSIBLE_KEYS)
        return KeyEvent(key_name)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().press(self.name)
        return True


class UIEvent(AppEvent):
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
            event_type = weighted_choice(choices)
            return event_type.get_random_instance(device, app)


class TouchEvent(UIEvent):
    """
    a touch on screen
    """

    def __init__(self, x, y, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'touch'
        self.x = x
        self.y = y

    @staticmethod
    def get_random_instance(device, app):
        x = random.uniform(0, device.get_display_info()['width'])
        y = random.uniform(0, device.get_display_info()['height'])
        return TouchEvent(x, y)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().longTouch(self.x, self.y, duration=500)
        return True


class LongTouchEvent(UIEvent):
    """
    a long touch on screen
    """

    def __init__(self, x, y, duration=2000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'long_touch'
        self.x = x
        self.y = y
        self.duration = duration

    @staticmethod
    def get_random_instance(device, app):
        x = random.uniform(0, device.get_display_info()['width'])
        y = random.uniform(0, device.get_display_info()['height'])
        return LongTouchEvent(x, y)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().longTouch(self.x, self.y, self.duration)
        return True


class DragEvent(UIEvent):
    """
    a drag gesture on screen
    """

    def __init__(self, start_x, start_y, end_x, end_y, duration=1000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'drag'
        self.start_x = start_x
        self.start_y = start_y
        self.end_x = end_x
        self.end_y = end_y
        self.duration = duration

    @staticmethod
    def get_random_instance(device, app):
        start_x = random.uniform(0, device.get_display_info()['width'])
        start_y = random.uniform(0, device.get_display_info()['height'])
        end_x = random.uniform(0, device.get_display_info()['width'])
        end_y = random.uniform(0, device.get_display_info()['height'])
        return DragEvent(start_x, start_y, end_x, end_y)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().drag((self.start_x, self.start_y),
                              (self.end_x, self.end_y),
                              self.duration)
        return True


class TypeEvent(UIEvent):
    """
    type some word
    """

    def __init__(self, text, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'type'
        self.text = text

    def send(self, device):
        assert device.get_adb() is not None
        escaped = self.text.replace('%s', '\\%s')
        encoded = escaped.replace(' ', '%s')
        device.adb.type(encoded)
        return True


class IntentEvent(AppEvent):
    """
    An event describing an intent
    """

    def __init__(self, intent, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'intent'
        self.intent = intent.get_cmd()

    @staticmethod
    def get_random_instance(device, app):
        action = random.choice(POSSIBLE_ACTIONS)
        intent = Intent(prefix='broadcast', action=action)
        return IntentEvent(intent)

    def send(self, device):
        device.get_adb().shell(self.intent)
        return True


class EmulatorEvent(AppEvent):
    """
    build-in emulator event, including incoming call and incoming SMS
    """

    def __init__(self, event_name, event_data=None, event_dict=None):
        """
        :param event_name: name of event
        :param event_data: data of event
        """
        if event_data is None:
            event_data = {}
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = 'emulator'
        self.event_name = event_name
        self.event_data = event_data

    def send(self, device):
        """
        :param device: Device
        """
        if self.event_name == 'call':
            if self.event_data and 'phone' in self.event_data.keys():
                phone = self.event_data['phone']
                device.receive_call(phone)
                time.sleep(2)
                device.accept_call(phone)
                time.sleep(2)
                device.cancel_call(phone)
            else:
                device.receive_call()
                time.sleep(2)
                device.accept_call()
                time.sleep(2)
                device.cancel_call()

        elif self.event_name == 'sms':
            if self.event_data and 'phone' in self.event_data.keys() \
                    and 'content' in self.event_data.keys():
                phone = self.event_data['phone']
                content = self.event_data['content']
                device.receive_sms(phone, content)
            else:
                device.receive_sms()

        else:
            raise UnknownEventException
        return True

    @staticmethod
    def get_random_instance(device, app):
        event_name = random.choice(['call', 'sms'])
        return EmulatorEvent(event_name=event_name)


class ContextEvent(AppEvent):
    """
    An extended event, which knows the device context in which it is performing
    This is reproducable
    """

    @staticmethod
    def get_random_instance(device, app):
        raise NotImplementedError

    def __init__(self, context, event, event_dict=None):
        """
        construct an event which knows its context
        :param context: the context where the event happens
        :param event: the event to perform
        """
        if event_dict is not None:
            assert 'event_type' in event_dict.keys()
            assert 'context' in event_dict.keys()
            assert 'event' in event_dict.keys()
            assert event_dict['event_type'] == 'context'
            self.event_type = event_dict['event_type']

            context_dict = event_dict['context']
            context_type = context_dict['context_type']
            ContextType = CONTEXT_TYPES[context_type]
            self.context = ContextType(context_dict=context_dict)

            sub_event_dict = event_dict['event']
            sub_event_type = sub_event_dict['event_type']
            SubEventType = EVENT_TYPES[sub_event_type]
            self.event = SubEventType(dict=sub_event_dict)
            return

        assert isinstance(event, AppEvent)
        self.event_type = 'context'
        self.context = context
        self.event = event

    def send(self, device):
        """
        to send a ContextEvent:
        assert the context matches the device, then send the event
        """
        if not self.context.assert_in_device(device):
            device.logger.warning("Context not in device: %s" % self.context.__str__())
        return self.event.send(device)

    def to_dict(self):
        return {'event_type': self.event_type, 'context': self.context.__dict__, 'event': self.event.__dict__}


class Context(object):
    """
    base class of context
    """

    def assert_in_device(self, device):
        """
        assert that the context is currently in device
        """
        return NotImplementedError


class ActivityNameContext(Context):
    """
    use activity name as context
    """

    def __init__(self, activity_name, context_dict=None):
        if context_dict is not None:
            self.__dict__ = context_dict
            return
        self.context_type = 'activity'
        self.activity_name = activity_name

    def __eq__(self, other):
        return self.activity_name == other.activity_name

    def __str__(self):
        return self.activity_name

    def assert_in_device(self, device):
        current_top_activity = device.get_adb().getTopActivityName()
        return self.activity_name == current_top_activity


class WindowNameContext(Context):
    """
    use window name as context
    """

    def __init__(self, window_name, context_dict=None):
        if context_dict is not None:
            self.__dict__ = context_dict
            return
        self.context_type = 'window'
        self.window_name = window_name

    def __eq__(self, other):
        return self.window_name == other.window_name

    def __str__(self):
        return self.window_name

    def assert_in_device(self, device):
        current_focused_window = device.get_adb().getFocusedWindowName()
        return self.window_name == current_focused_window


CONTEXT_TYPES = {
    'activity': ActivityNameContext,
    'window': WindowNameContext
}


class UniqueView(object):
    """
    use view unique id and its text to identify a view
    """

    def __init__(self, unique_id, text):
        self.unique_id = unique_id
        self.text = text

    def __eq__(self, other):
        return self.unique_id == other.unique_id and self.text == other.text

    def __str__(self):
        return "%s/%s" % (self.unique_id, self.text)


class AppEventManager(object):
    """
    This class manages all events to send during app running
    """

    def __init__(self, device, app, event_policy, event_count, event_interval, event_duration):
        """
        construct a new AppEventManager instance
        :param device: instance of Device
        :param app: instance of App
        :param event_policy: policy of generating events, string
        :return:
        """
        self.logger = logging.getLogger('AppEventManager')
        self.enabled = True

        self.device = device
        self.app = app
        self.policy = event_policy
        self.events = []
        self.event_factory = None
        self.event_count = event_count
        self.event_interval = event_interval
        self.event_duration = event_duration
        self.monkey = None
        self.timer = None

        if not self.event_count or self.event_count is None:
            self.event_count = 100

        if not self.policy or self.policy is None:
            self.policy = "monkey"

        if not self.event_interval or self.event_interval is None:
            self.event_interval = 2

        if self.policy == "none":
            self.event_factory = NoneEventFactory(device, app)
        elif self.policy == "monkey":
            self.event_factory = None
        elif self.policy == "random":
            self.event_factory = RandomEventFactory(device, app)
        elif self.policy == "static":
            self.event_factory = StaticEventFactory(device, app)
        elif self.policy == "dynamic":
            self.event_factory = DynamicEventFactory(device, app)
        else:
            self.event_factory = FileEventFactory(device, app, self.policy)

    def add_event(self, event):
        """
        add one event to the event list
        :param event: the event to be added, should be subclass of AppEvent
        :return:
        """
        if event is None:
            return
        self.events.append(event)
        self.device.send_event(event)

    def dump(self, out_file):
        """
        dump the event information to a file
        :param out_file: the file to output the events
        :return:
        """
        event_array = []
        for event in self.events:
            event_array.append(event.to_dict())
        event_json = json.dumps(event_array)
        out_file.write(event_json)

    # def on_state_update(self, old_state, new_state):
    #     """
    #     callback method invoked by AppstateMonitor
    #     :param old_state: origin state of App
    #     :param new_state: new state of App
    #     :return:
    #     """
    #

    def set_event_factory(self, event_factory):
        """
        set event factory of the app
        :param event_factory: the factory used to generate events
        :return:
        """
        self.event_factory = event_factory

    def start(self):
        """
        start sending event
        """
        self.logger.info("start sending events, policy is %s" % self.policy)

        if self.event_duration:
            self.timer = Timer(self.event_duration, self.stop)
            self.timer.start()

        try:
            if self.event_factory is not None:
                self.event_factory.start(self)
            else:
                throttle = self.event_interval * 1000
                monkey_cmd = "adb shell monkey %s --throttle %d -v %d" % (
                    ("" if self.app.get_package_name() is None else "-p " + (self.app.get_package_name())),
                    throttle, self.event_count)
                self.monkey = subprocess.Popen(monkey_cmd.split(),
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                while self.enabled:
                    time.sleep(1)
        except KeyboardInterrupt:
            pass
        out_file = open(os.path.join(self.device.output_dir, "droidbot_event.json"), "w")
        self.dump(out_file)
        out_file.close()
        self.logger.info("finish sending events, saved to droidbot_event.json")

    def stop(self):
        """
        stop sending event
        """
        if self.monkey:
            self.monkey.terminate()
            self.monkey = None
        if self.timer and self.timer.isAlive():
            self.timer.cancel()
        self.enabled = False


class EventFactory(object):
    """
    This class is responsible for generating events to stimulate more app behaviour
    It should call AppEventManager.send_event method continuously
    """

    def __init__(self, device, app):
        self.device = device
        self.app = app

    def start(self, event_manager):
        """
        start producing events
        :param event_manager: instance of AppEventManager
        """
        count = 0
        while event_manager.enabled and count < event_manager.event_count:
            try:
                event = self.generate_event()
                event_manager.add_event(event)
                time.sleep(event_manager.event_interval)
            except KeyboardInterrupt:
                break
            except RuntimeError as e:
                self.device.logger.warning(e.message)
                break
            except Exception as e:
                self.device.logger.warning(e.message)
                continue
            count += 1

    def generate_event(self):
        """
        generate a event
        """
        raise NotImplementedError


class NoneEventFactory(EventFactory):
    """
    do not send any event
    """

    def __init__(self, device, app):
        super(NoneEventFactory, self).__init__(device, app)

    def generate_event(self):
        """
        generate a event
        """
        return None


class RandomEventFactory(EventFactory):
    """
    A dummy factory which produces AppEventManager.send_event method in a random manner
    """

    def __init__(self, device, app):
        super(RandomEventFactory, self).__init__(device, app)
        self.choices = {
            UIEvent: 7,
            IntentEvent: 2,
            KeyEvent: 1
        }

    def generate_event(self):
        """
        generate a event
        """
        event_type = weighted_choice(self.choices)
        event = event_type.get_random_instance(self.device, self.app)
        return event


class StaticEventFactory(EventFactory):
    """
    A factory which produces events based on static analysis result
    for example, manifest file and sensitive API it used
    """

    def __init__(self, device, app):
        super(StaticEventFactory, self).__init__(device, app)
        self.choices = {
            UIEvent: 5,
            IntentEvent: 4,
            KeyEvent: 1
        }
        self.possible_broadcasts = app.get_possible_broadcasts()

    def generate_event(self):
        """
        generate a event
        """
        event_type = weighted_choice(self.choices)
        if event_type == IntentEvent and self.possible_broadcasts:
            event = IntentEvent(random.choice(list(self.possible_broadcasts)))
        else:
            event = event_type.get_random_instance(self.device, self.app)
        return event


class DynamicEventFactory(EventFactory):
    """
    A much wiser factory which produces events based on the current app state
    for each service, try sending all broadcasts
    for each activity, try touching each view, and scrolling in four directions
    """

    def __init__(self, device, app):
        super(DynamicEventFactory, self).__init__(device, app)
        assert device.get_adb() is not None
        assert device.get_view_client() is not None

        self.exploited_contexts = set()
        self.exploited_services = set()
        self.exploited_broadcasts = set()

        # a map of Context to UniqueViews,
        # which means the views are exploited in the context
        self.exploited_views = {}
        self.saved_views = {}
        self.window_passes = {}
        self.window_pass_limit = 3

        self.previous_event = None
        self.previous_activity = None
        self.event_stack = []

        self.possible_broadcasts = app.get_possible_broadcasts()

        self.possible_inputs = {
            'account': 'droidbot',
            'name': 'droidbot',
            'email': 'droidbot@honeynet.com',
            'password': 'droidbot',
            'pwd': 'droidbot',
            'text': 'hello world',
            'number': '1234567890'
        }

        # randomized touch events for each webview
        self.webview_touches = 5

        self.preferred_buttons = ["yes", "ok", "activate", "detail", "more",
                                  "check", "agree", "try", "go", "next"]

        if self.device.is_emulator:
            self.choices = {
                UIEvent: 40,
                IntentEvent: 8,
                KeyEvent: 1,
                EmulatorEvent: 1
            }
        else:
            self.choices = {
                UIEvent: 40,
                IntentEvent: 9,
                KeyEvent: 1
            }

        # use this flag to indicate the last sent event
        self.last_event_flag = ""

    def generate_event(self):
        if self.event_stack:
            event = self.event_stack.pop()
            return event
        else:
            return self.find_events()

    def find_events(self):
        """
        find some event, return the first, and add the rest to event stack
        """
        # get current running Activity
        top_activity_name = self.device.get_adb().getTopActivityName()
        # if the activity switches, wait a few seconds
        if top_activity_name != self.previous_activity:
            time.sleep(3)
        self.previous_activity = top_activity_name

        # get focused window
        focused_window = self.device.get_adb().getFocusedWindow()
        focused_window_id = -1
        focused_window_name = None
        if focused_window is not None:
            focused_window_id = focused_window.winId
            focused_window_name = focused_window.activity

        current_context = WindowNameContext(window_name=focused_window_name)
        current_context_str = current_context.__str__()

        # get running services
        running_services = set(self.device.get_service_names())
        new_services = running_services - self.exploited_services
        # if new service is started, set exploited broadcasts to empty
        if new_services:
            self.exploited_services = self.exploited_services.union(running_services)
            self.exploited_broadcasts = set()

        event_type = weighted_choice(self.choices)

        if event_type == IntentEvent and self.possible_broadcasts:
            possible_intents = self.possible_broadcasts - self.exploited_broadcasts
            if not possible_intents:
                possible_intents = self.possible_broadcasts
                self.exploited_broadcasts = set()
            intent = random.choice(list(possible_intents))
            self.exploited_broadcasts.add(intent)
            intent_event = IntentEvent(intent=intent)

            return ContextEvent(context=current_context, event=intent_event)

        if event_type == KeyEvent or event_type == EmulatorEvent:
            event = KeyEvent.get_random_instance(self.device, self.app)

            return ContextEvent(context=current_context, event=event)

        # if the current context is exploited, try go back
        if current_context_str in self.exploited_contexts:
            if self.last_event_flag.endswith("start_app+back+start_app") or \
                    self.last_event_flag.endswith("start_app+back+back+home+start_app"):
                # It seems the views in app is all explored
                # Then give it another pass
                self.exploited_contexts.clear()
                self.exploited_services.clear()
                self.exploited_broadcasts.clear()
                self.saved_views.clear()
                self.window_passes.clear()
                self.exploited_views.clear()
            elif self.last_event_flag.endswith("back+back"):
                # It seems the app can not be back, try use HOME key
                self.last_event_flag += "+home"
                event = ContextEvent(context=current_context, event=KeyEvent('HOME'))
                return event
            elif self.last_event_flag.endswith("back+back+home"):
                # HOME key also does not work
                self.device.logger.warning("This app might have hijacked the device!")
                # we have to continue interacting with this app
                self.exploited_contexts.clear()
                self.exploited_services.clear()
                self.exploited_broadcasts.clear()
                self.saved_views.clear()
                self.window_passes.clear()
                self.exploited_views.clear()
            else:
                self.last_event_flag += "+back"
                event = ContextEvent(context=current_context, event=KeyEvent('BACK'))
                return event

        if not self.device.is_foreground(self.app):
            if self.last_event_flag.endswith("+start_app"):
                # It seems the app stuck at some state, and cannot be started
                # just pass to let viewclient deal with this case
                pass
            else:
                self.last_event_flag += "+start_app"
                component = self.app.get_package_name()
                if self.app.get_main_activity():
                    component += "/%s" % self.app.get_main_activity()
                return IntentEvent(Intent(suffix=component))

        if current_context_str not in self.exploited_views.keys():
            self.exploited_views[current_context_str] = set()

        # if no views were saved, dump view via AndroidViewClient
        if current_context_str not in self.saved_views.keys():
            views = self.device.get_view_client().dump(window=focused_window_id)
            self.saved_views[current_context_str] = views
            self.window_passes[current_context_str] = 0
        else:
            views = self.saved_views[current_context_str]

        # then find a view to send UI event
        random.shuffle(views)

        # find preferred view
        for v in views:
            if v.getChildren() or v.getWidth() == 0 or v.getHeight() == 0:
                continue

            unique_view_str = UniqueView(unique_id=v.getUniqueId(), text=v.getText()).__str__()
            if unique_view_str in self.exploited_views[current_context_str]:
                continue

            v_text = v.getText()
            if v_text is None:
                continue
            v_text = v_text.lower()
            if v_text in self.preferred_buttons:
                self.exploited_views[current_context_str].add(unique_view_str)
                (x, y) = v.getCenter()
                event = TouchEvent(x, y)
                self.event_stack.append(event)
                self.last_event_flag = "touch"
                return event

        # no preferred view, find another
        for v in views:
            if v.getChildren() or v.getWidth() == 0 or v.getHeight() == 0:
                continue

            unique_view_str = UniqueView(unique_id=v.getUniqueId(), text=v.getText()).__str__()
            if unique_view_str in self.exploited_views[current_context_str]:
                continue

            self.exploited_views[current_context_str].add(unique_view_str)
            (x, y) = v.getCenter()
            event = ContextEvent(context=current_context, event=TouchEvent(x, y))
            v_cls_name = v.getClass().lower()

            # if it is an EditText, try input something
            from com.dtmilano.android.viewclient import EditText
            if isinstance(v, EditText) or 'edit' in v_cls_name\
                    or 'text' in v_cls_name or 'input' in v_cls_name:
                for key in self.possible_inputs.keys():
                    if key in v.getId().lower() or key in v_cls_name:
                        next_event = TypeEvent(text=self.possible_inputs[key])
                        self.event_stack.append(next_event)
                        break

            # if it is a WebView, try touch randomly
            if 'webview' in v_cls_name:
                webview_event_count = 0
                bounds = v.getBounds()
                while webview_event_count < self.webview_touches:
                    webview_x = random.uniform(bounds[0][0], bounds[1][0])
                    webview_y = random.uniform(bounds[1][1], bounds[0][1])
                    self.event_stack.append(TouchEvent(webview_x, webview_y))
                    webview_event_count += 1

            self.last_event_flag = "touch"
            return event
        # if reach here, it means droidbot has traverse current window once more
        self.window_passes[current_context_str] += 1
        if self.window_passes[current_context_str] < self.window_pass_limit:
            self.exploited_views[current_context_str] = set()
        else:
            # Then mark this context as exploited
            self.exploited_contexts.add(current_context_str)

        # if all views were exploited, TODO try scroll current view

        self.last_event_flag += "back"
        event = ContextEvent(context=current_context, event=KeyEvent('BACK'))
        return event


EVENT_TYPES = {
    'key': KeyEvent,
    'touch': TouchEvent,
    'long_touch': LongTouchEvent,
    'drag': DragEvent,
    'type': TypeEvent,
    'emulator': EmulatorEvent,
    'context': ContextEvent
}


class FileEventFactory(EventFactory):
    """
    factory which produces events from file
    """

    def __init__(self, device, app, in_file):
        """
        create a FileEventFactory from a json file
        :param in_file path string
        """
        super(FileEventFactory, self).__init__(device, app)
        self.events = []
        self.file = in_file
        f = open(in_file, 'r')
        events_json = f.readall()
        events_array = json.loads(events_json)
        for event_dict in events_array:
            if not isinstance(event_dict, dict):
                raise UnknownEventException
            if 'event_type' not in event_dict.keys():
                raise UnknownEventException
            event_type = event_dict['event_type']
            if 'event_type' not in EVENT_TYPES.keys():
                raise UnknownEventException
            EventType = EVENT_TYPES[event_type]
            event = EventType(dict=event_dict)
            self.events.append(event)
        self.index = 0

    def generate_event(self):
        """
        generate a event
        """
        event = self.events[self.index]
        self.index += 1
        return event


class CustomizedEventFactory(EventFactory):
    """
    factory with customized actions
    """

    def __init__(self, device, app, gen_event_based_on_state=None):
        super(CustomizedEventFactory, self).__init__(device, app)
        self.device = device
        self.app = app
        self.gen_event_based_on_state = gen_event_based_on_state
        if self.gen_event_based_on_state is None:
            self.gen_event_based_on_state = self.gen_default_event_based_on_state

    def generate_event(self):
        state = self.device.get_current_state()
        return self.gen_event_based_on_state(state)

    def gen_default_event_based_on_state(self, state):
        """
        randomly select a view and click it
        @param state:
        @return:
        """
        pass
