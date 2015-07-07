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
        device.get_adb().touch(self.x, self.y)


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


class IntentEvent(AppEvent):
    """
    An event describing an intent
    """
    def __init__(self, intent, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
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
    def __init__(self, event_name, event_data={}, event_dict=None):
        """
        :param event_name: name of event
        :param event_data: data of event
        """
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.type = 'emulator'
        self.event_name = event_name
        self.event_data = event_data

    def send(self, device):
        assert isinstance(device, Device)
        if self.event_name == 'call':
            if self.event_data and self.event_data.has_key('phone'):
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
            if self.event_data and self.event_data.has_key('phone') \
                and self.event_data.has_key('content'):
                phone = self.event_data['phone']
                content = self.event_data['content']
                device.receive_sms(phone, content)
            else:
                device.receive_sms()

        else:
            raise UnknownEventException

    @staticmethod
    def get_random_instance(device, app):
        event_name = random.choice(['call', 'sms'])
        return EmulatorEvent(event_name=event_name)

class ContextEvent(AppEvent):
    """
    An extended event, which knows the device context in which it is performing
    This is reproducable
    """
    def __init__(self, context, event, event_dict=None):
        """
        construct an event which knows its context
        :param context: the context where the event happens
        :param event: the event to perform
        """
        if event_dict is not None:
            assert event_dict.has_key('type')
            assert event_dict.has_key('context')
            assert event_dict.has_key('event')
            assert event_dict['type'] == 'context'
            self.type = event_dict['type']

            context_dict = event_dict['context']
            context_type = context_dict['type']
            ContextType = CONTEXT_TYPES[context_type]
            self.context = ContextType(context_dict=context_dict)

            sub_event_dict = event_dict['event']
            sub_event_type = sub_event_dict['type']
            SubEventType = EVENT_TYPES[sub_event_type]
            self.event = SubEventType(dict=sub_event_dict)
            return

        assert isinstance(event, AppEvent)
        self.type = 'context'
        self.context = context
        self.event = event

    def send(self, device):
        """
        to send a ContextEvent:
        assert the context matches the device, then send the event
        """
        assert isinstance(device, Device)
        assert self.context.assert_in_device(device)
        self.event.send(device)

    def to_dict(self):
        return {'type': self.type, 'context': self.context.__dict__, 'event': self.event.__dict__}


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
        self.type = 'activity'
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
        self.type = 'window'
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
        return self.unique_id == other.unique_id \
               and self.text == other.text

    def __str__(self):
        return "%s/%s" % (self.unique_id, self.text)


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
        f = open(file, 'w')
        event_array = []
        for event in self.events:
            event_array.append(event.to_dict())
        event_json = json.dumps(event_array)
        f.write(event_json)

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
        if event_type == IntentEvent:
            event = IntentEvent(random.choice(self.possible_broadcasts))
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

        self.previous_event = None
        self.previous_activity = None
        self.event_stack = []

        self.possible_broadcasts = set(app.get_possible_broadcasts())
        self.possible_inputs = {
            'account': 'droidbot',
            'name': 'droidbot',
            'email': 'droidbot@honeynet.com',
            'password': 'droidbot',
            'pwd': 'droidbot',
            'text': 'hello world',
            'number': '1234567890'
        }

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
        current_context = WindowNameContext(window_name=focused_window.activity)
        current_context_str = current_context.__str__()
        # get running services
        running_services = set(self.device.get_adb().getServiceNames())
        new_services = running_services - self.exploited_services
        # if new service is started, set exploited broadcasts to empty
        if new_services:
            self.exploited_services = self.exploited_services.union(running_services)
            self.exploited_broadcasts = set()

        event_type = weighted_choice(self.choices)

        if event_type == IntentEvent:
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

        # if the current activity is exploited, try go back
        if current_context_str in self.exploited_contexts:
            event = ContextEvent(context=current_context, event=KeyEvent('BACK'))
            return event

        if not self.device.is_foreground(self.app):
            return IntentEvent(Intent(suffix="%s/%s" %
                                             (self.app.get_package_name(),
                                              self.app.get_main_activity())))

        if not self.exploited_views.has_key(current_context_str):
            self.exploited_views[current_context_str] = set()

        # if no views were saved, dump view via AndroidViewClient
        if not self.saved_views.has_key(current_context_str):
            views = self.device.get_view_client().dump(window=focused_window.winId)
            self.saved_views[current_context_str] = views
        else:
            views = self.saved_views[current_context_str]

        # then find a view to send UI event
        random.shuffle(views)
        for v in views:
            if v.getChildren() or v.getWidth() == 0 or v.getHeight() == 0:
                continue
            unique_view_str = UniqueView(unique_id=v.getUniqueId(), text=v.getText()).__str__()
            if unique_view_str in self.exploited_views[current_context_str]:
                continue
            else:
                self.exploited_views[current_context_str].add(unique_view_str)
                (x, y) = v.getCenter()
                event = ContextEvent(context=current_context, event=TouchEvent(x, y))
                # if it is an EditText, try input something
                from com.dtmilano.android.viewclient import EditText

                if isinstance(v, EditText) or v.getClass().__contains__('EditText'):
                    for key in self.possible_inputs.keys():
                        if v.getId().__contains__(key) or v.getClass().__contains__(key):
                            next_event = TypeEvent(text=self.possible_inputs[key])
                            self.event_stack.append(next_event)
                            break
                return event
        # if all views were exploited, TODO try scroll current view
        # Then mark this context as exploited
        self.exploited_contexts.add(current_context_str)
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
    def __init__(self, device, app, file):
        """
        create a FileEventFactory from a json file
        :param file path string
        """
        super(FileEventFactory, self).__init__(device, app)
        self.events = []
        self.file = file
        f = open(file, 'r')
        events_json = f.readall()
        events_array = json.loads(events_json)
        for event_dict in events_array:
            if not isinstance(event_dict, dict):
                raise UnknownEventException
            if not event_dict.has_key('event_type'):
                raise UnknownEventException
            event_type = event_dict['event_type']
            if not EVENT_TYPES.has_key('event_type'):
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