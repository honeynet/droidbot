# This file is responsible for generating events to interact with app at runtime
# The events includes:
#     1. UI events. click, touch, etc
#     2, intent events. broadcast events of App installed, new SMS, etc.
# The intention of these events is to exploit more mal-behaviours of app as soon as possible
__author__ = 'liyc'
import logging
import json
import time
import random
from types import Intent, Device, App

EVENT_POLICIES = [
    "none",
    "monkey",
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


class UnknownEventException(Exception):
    pass


class AppEvent(object):
    """
    The base class of all events
    """
    def to_dict(self):
        return self.__dict__

    def to_json(self):
        json.dumps(self.to_dict())

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
    def __init__(self, name):
        self.event_type = 'key'
        self.name = name

    @staticmethod
    def get_random_instance(device, app):
        key_name = random.choice(POSSIBLE_KEYS)
        return KeyEvent(key_name)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().press(self.name)


class UIEvent(AppEvent):
    """
    This class describes a UI event of app, such as touch, click, etc
    """
    @staticmethod
    def get_random_instance(device, app):
        if not device.is_foreground(app):
            # if current app is in background, bring it to foreground
            return IntentEvent(Intent(suffix=app.get_package_name()))
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
    def __init__(self, x, y):
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
        device.get_adb().touch(self.x, self.y)


class LongTouchEvent(UIEvent):
    """
    a long touch on screen
    """
    def __init__(self, x, y, duration=2000):
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


class DragEvent(UIEvent):
    """
    a drag gesture on screen
    """
    def __init__(self, start_x, start_y, end_x, end_y, duration=1000):
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

class IntentEvent(AppEvent):
    """
    An event describing an intent
    """
    def __init__(self, intent):
        assert isinstance(intent, Intent)
        self.type = 'intent'
        self.intent = intent.get_cmd()

    @staticmethod
    def get_random_instance(device, app):
        action = random.choice(POSSIBLE_ACTIONS)
        intent = Intent(prefix='broadcast', action=action)
        return IntentEvent(intent)

    def send(self, device):
        assert device.get_adb() is not None
        device.get_adb().shell(self.intent)


class EmulatorEvent(AppEvent):
    """
    build-in emulator event, including incoming call and incoming SMS
    """
    def __init__(self, event_name, event_data):
        """
        :param event_name: name of event
        :param event_data: data of event
        """
        self.event_name = event_name
        self.event_data = event_data

    def send(self, device):
        assert isinstance(device, Device)
        if self.event_data == 'call':
            device.receive_call()
            time.sleep(2)
            device.accept_call()
        elif self.event_data == 'sms':
            device.send_sms()
        else:
            raise UnknownEventException

class ContextEvent(AppEvent):
    """
    An extended event, which knows the device context in which it is performing
    This is reproducable
    """
    def __init__(self, context, event):
        """
        construct an event which knows its context
        :param context: the context where the event happens
        :param event: the event to perform
        """
        assert isinstance(event, UIEvent)
        self.type = 'context'
        self.context = context
        self.event = event

    def to_dict(self):
        return {'context' : self.context.__dict__, 'event' : self.event.__dict__}


class AppEventManager(object):
    """
    This class manages all events to send during app running
    """

    def __init__(self, device, app, event_policy, event_count, event_duration=2):
        """
        construct a new AppEventManager instance
        :param device: instance of Device
        :param app: instance of App
        :param event_policy: policy of generating events, string
        :return:
        """
        self.logger = logging.getLogger('AppEventManager')
        self.device = device
        self.app = app
        self.policy = event_policy
        self.events = []
        self.event_factory = None
        self.count = event_count
        self.duration = event_duration

        if not self.count or self.count == None:
            self.count = 100

        if not self.policy or self.policy == None:
            self.policy = "monkey"

        if self.policy == "none":
            self.event_factory = None
        elif self.policy == "monkey":
            self.event_factory = DummyEventFactory(device, app)
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
        self.events.append(event)
        self.device.send_event(event)

    def dump(self, file):
        """
        dump the event information to a file
        :param file: the file path to output the events
        :return:
        """
        # TODO implement this method

    def on_state_update(self, old_state, new_state):
        """
        callback method invoked by AppstateMonitor
        :param old_state: origin state of App
        :param new_state: new state of App
        :return:
        """
        # TODO implement this method

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
        if self.event_factory is not None:
            self.event_factory.start(self)
        else:
            monkey_cmd = "monkey %s --throttle 1000 -v %d" % (
                ("" if self.app.get_package_name() is None else "-p " + (self.app.get_package_name())),
                self.count
            )
            self.device.get_adb().shell(" ".join(monkey_cmd))
        self.logger.info("finish sending events, policy is %s" % self.policy)


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
        while count < event_manager.count:
            event = self.generate_event()
            event_manager.add_event(event)
            time.sleep(event_manager.duration)
            count += 1

    def generate_event(self):
        """
        generate a event
        """
        raise NotImplementedError


def weighted_choice(choices):
    total = sum(choices[c] for c in choices.keys())
    r = random.uniform(0, total)
    upto = 0
    for c in choices.keys():
        if upto + choices[c] > r:
            return c
        upto += choices[c]


class DummyEventFactory(EventFactory):
    """
    A dummy factory which produces AppEventManager.send_event method in a random manner
    """

    def __init__(self, device, app):
        super(DummyEventFactory, self).__init__(device, app)
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
        androguard_a = app.get_androguard_analysis().a
        receivers = androguard_a.get_receivers()
        self.choices = {
            UIEvent: 5,
            IntentEvent: 4,
            KeyEvent: 1
        }
        self.possible_intents = set()
        for receiver in receivers:
            intent_filters = androguard_a.get_intent_filters('receiver', receiver)
            actions = intent_filters['action']
            categories = intent_filters['category']
            categories.append(None)
            for action in actions:
                for category in categories:
                    intent = Intent(prefix='broadcast', action=action, category=category)
                    self.possible_intents.add(intent)

    def generate_event(self):
        """
        generate a event
        """
        event_type = weighted_choice(self.choices)
        if event_type == IntentEvent:
            event = IntentEvent(random.choice(self.possible_intents))
        else:
            event = event_type.get_random_instance(self.device, self.app)
        return event


class DynamicEventFactory(EventFactory):
    """
    A much wiser factory which produces events based on the current app state
    """

    def __init__(self, device, app):
        super(DynamicEventFactory, self).__init__(device, app)

    def generate_event(self):
        """
        generate a event
        """
        pass



class FileEventFactory(EventFactory):
    """
    factory which produces events from file
    """
    def __init__(self, device, app, file):
        """
        create a FileEventFactory from a json file
        :param file path string
        """
        super(FileEventFactory, self).__init__(device, app)
        self.file = file

    def generate_event(self):
        """
        generate a event
        """
        pass