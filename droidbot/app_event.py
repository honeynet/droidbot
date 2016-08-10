# This file is responsible for generating events to interact with app at runtime
# The events includes:
#     1. UI events. click, touch, etc
#     2, intent events. broadcast events of App installed, new SMS, etc.
# The intention of these events is to exploit more mal-behaviours of app as soon as possible
import json
import logging
import os
import random
import subprocess
import time
from threading import Timer
from intent import Intent
from device import DeviceState

POLICY_NONE = "none"
POLICY_STATE_RECORDER = "state_recorder"
POLICY_MONKEY = "monkey"
POLICY_RANDOM = "random"
POLICY_STATIC = "static"
POLICY_DYNAMIC = "dynamic"
POLICY_UTG_DYNAMIC = "utg_dynamic"
POLICY_MANUAL = "manual"
POLICY_FILE = "file"

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

KEY_KeyEvent = "key"
KEY_TouchEvent = "touch"
KEY_LongTouchEvent = "long_touch"
KEY_DragEvent = "drag"
KEY_SwipeEvent = "swipe"
KEY_TypeEvent = "type"
KEY_IntentEvent = "intent"
KEY_EmulatorEvent = "emulator"
KEY_ContextEvent = "context"


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

    @staticmethod
    def get_event(event_dict):
        if not isinstance(event_dict, dict):
            return None
        if 'event_type' not in event_dict:
            return None
        event_type = event_dict['event_type']
        if event_type == KEY_KeyEvent:
            return KeyEvent(None, event_dict=event_dict)
        elif event_type == KEY_TouchEvent:
            return TouchEvent(None, None, event_dict=event_dict)
        elif event_type == KEY_LongTouchEvent:
            return LongTouchEvent(None, None, event_dict=event_dict)
        elif event_type == KEY_DragEvent:
            return DragEvent(None, None, None, None, event_dict=event_dict)
        elif event_type == KEY_SwipeEvent:
            return SwipeEvent(None, None, event_dict=event_dict)
        elif event_type == KEY_TypeEvent:
            return TypeEvent(None, event_dict=event_dict)
        elif event_type == KEY_IntentEvent:
            return IntentEvent(None, event_dict=event_dict)
        elif event_type == KEY_EmulatorEvent:
            return EmulatorEvent(None, None, event_dict=event_dict)
        elif event_type == KEY_ContextEvent:
            return ContextEvent(None, None, event_dict=event_dict)


class KeyEvent(AppEvent):
    """
    a key pressing event
    """
    def __init__(self, name, event_dict=None):
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
        self.event_type = KEY_TouchEvent
        self.x = x
        self.y = y

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

    def __init__(self, x, y, duration=2000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_LongTouchEvent
        self.x = x
        self.y = y
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
    def __init__(self, start_x, start_y, end_x, end_y, duration=1000, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_DragEvent
        self.start_x = start_x
        self.start_y = start_y
        self.end_x = end_x
        self.end_y = end_y
        self.duration = duration

    @staticmethod
    def get_random_instance(device, app):
        start_x = random.uniform(0, device.get_width())
        start_y = random.uniform(0, device.get_height())
        end_x = random.uniform(0, device.get_width())
        end_y = random.uniform(0, device.get_height())
        return DragEvent(start_x, start_y, end_x, end_y)

    def send(self, device):
        device.view_drag((self.start_x, self.start_y),
                         (self.end_x, self.end_y),
                         self.duration)
        return True


class SwipeEvent(UIEvent):
    """
    swipe gesture
    """
    def __init__(self, x, y, direction="UP", event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_SwipeEvent
        self.x = x
        self.y = y
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


class TypeEvent(UIEvent):
    """
    type some word
    """

    @staticmethod
    def get_random_instance(device, app):
        pass

    def __init__(self, text, event_dict=None):
        if event_dict is not None:
            self.__dict__ = event_dict
            return
        self.event_type = KEY_TypeEvent
        self.text = text

    def send(self, device):
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
        self.event_type = KEY_IntentEvent
        self.intent = intent.get_cmd() if isinstance(intent, Intent) else ""

    @staticmethod
    def get_random_instance(device, app):
        action = random.choice(POSSIBLE_ACTIONS)
        from intent import Intent
        intent = Intent(prefix='broadcast', action=action)
        return IntentEvent(intent)

    def send(self, device):
        device.send_intent(intent=self.intent)
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
        self.event_type = KEY_EmulatorEvent
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
    This is reproducible
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
            assert KEY_ContextEvent in event_dict.keys()
            assert 'event' in event_dict.keys()
            assert event_dict['event_type'] == KEY_ContextEvent
            self.event_type = event_dict['event_type']

            context_dict = event_dict[KEY_ContextEvent]
            context_type = context_dict['context_type']
            ContextType = CONTEXT_TYPES[context_type]
            self.context = ContextType(context_dict=context_dict)

            sub_event_dict = event_dict['event']
            sub_event_type = sub_event_dict['event_type']
            SubEventType = EVENT_TYPES[sub_event_type]
            self.event = SubEventType(event_dict=sub_event_dict)
            return

        assert isinstance(event, AppEvent)
        self.event_type = KEY_ContextEvent
        self.context = context
        self.event = event

    def send(self, device):
        """
        to send a ContextEvent:
        assert the context matches the device, then send the event
        @param device: Device
        """
        if not self.context.assert_in_device(device):
            device.logger.warning("Context not in device: %s" % self.context.__str__())
        return self.event.send(device)

    def to_dict(self):
        return {'event_type': self.event_type, KEY_ContextEvent: self.context.__dict__, 'event': self.event.__dict__}


class Context(object):
    """
    base class of context
    """

    def assert_in_device(self, device):
        """
        assert that the context is currently in device
        @param device: Device
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
        current_top_activity = device.get_top_activity_name()
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
        current_focused_window = device.get_focused_window_name()
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
            self.policy = POLICY_NONE

        if not self.event_interval or self.event_interval is None:
            self.event_interval = 2

        self.event_factory = self.get_event_factory(self.policy, device, app)

    @staticmethod
    def get_event_factory(policy, device, app):
        if policy == POLICY_NONE:
            event_factory = None
        elif policy == POLICY_STATE_RECORDER:
            event_factory = None
        elif policy == POLICY_MONKEY:
            event_factory = None
        elif policy == POLICY_RANDOM:
            event_factory = RandomEventFactory(device, app)
        elif policy == POLICY_STATIC:
            event_factory = StaticEventFactory(device, app)
        elif policy == POLICY_DYNAMIC:
            event_factory = DynamicEventFactory(device, app)
        elif policy == POLICY_UTG_DYNAMIC:
            event_factory = UtgDynamicFactory(device, app)
        elif policy == POLICY_MANUAL:
            event_factory = ManualEventFactory(device, app)
        else:
            script_file_path = policy
            f = open(script_file_path, 'r')
            script_dict = json.load(f)
            event_factory = ScriptEventFactory(device, app, script_dict)
        return event_factory

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

    def dump(self):
        """
        dump the event information to files
        :return:
        """
        event_log_file = open(os.path.join(self.device.output_dir, "droidbot_event.json"), "w")
        event_array = []
        for event in self.events:
            event_array.append(event.to_dict())
        json.dump(event_array, event_log_file)
        event_log_file.close()
        if self.event_factory is not None:
            self.event_factory.dump()

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
            elif self.policy == POLICY_NONE:
                self.device.start_app(self.app)
                while self.enabled:
                    time.sleep(1)
            elif self.policy == POLICY_MONKEY:
                throttle = self.event_interval * 1000
                monkey_cmd = "adb -s %s shell monkey %s --throttle %d -v %d" % (
                    self.device.serial,
                    "" if self.app.get_package_name() is None else "-p " + self.app.get_package_name(),
                    throttle, self.event_count)
                self.monkey = subprocess.Popen(monkey_cmd.split(),
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                while self.enabled:
                    time.sleep(1)
            elif self.policy == POLICY_STATE_RECORDER:
                self.device.start_app(self.app)
                while self.enabled:
                    keyboard_input = raw_input("press ENTER to save current state, type q to exit...")
                    if keyboard_input.startswith('q'):
                        break
                    state = self.device.get_current_state()
                    if state is not None:
                        state.save2dir()
        except KeyboardInterrupt:
            pass

        self.stop()
        self.dump()
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
            self.timer = None
        self.enabled = False


class StopSendingEventException(Exception):
    def __init__(self, message):
        self.message = message


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
                # make sure the first event is go to HOME screen
                # the second event is to start the app
                if count == 0:
                    event = KeyEvent(name="HOME")
                elif count == 1:
                    event = IntentEvent(self.app.get_start_intent())
                else:
                    event = self.generate_event()
                event_manager.add_event(event)
                time.sleep(event_manager.event_interval)
            except KeyboardInterrupt:
                break
            except StopSendingEventException as e:
                self.device.logger.warning("EventFactory stop sending event: %s" % e)
                break
            # except RuntimeError as e:
            #     self.device.logger.warning(e.message)
            #     break
            except Exception as e:
                self.device.logger.warning("exception in EventFactory: %s" % e)
                import traceback
                traceback.print_exc()
                continue
            count += 1

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
        pass

    def dump(self):
        """
        dump something to file
        @return:
        """
        pass


class NoneEventFactory(EventFactory):
    """
    do not send any event
    """

    def __init__(self, device, app):
        super(NoneEventFactory, self).__init__(device, app)

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
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

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
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

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
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

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
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
        top_activity_name = self.device.get_top_activity_name()
        # if the activity switches, wait a few seconds
        if top_activity_name != self.previous_activity:
            time.sleep(3)
        self.previous_activity = top_activity_name

        # get focused window
        focused_window_name = self.device.get_focused_window_name()

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
            views = self.device.dump_views()
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
            if 'edit' in v_cls_name or 'text' in v_cls_name or 'input' in v_cls_name:
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
    KEY_KeyEvent: KeyEvent,
    KEY_TouchEvent: TouchEvent,
    KEY_LongTouchEvent: LongTouchEvent,
    KEY_DragEvent: DragEvent,
    KEY_SwipeEvent: SwipeEvent,
    KEY_TypeEvent: TypeEvent,
    KEY_IntentEvent: IntentEvent,
    KEY_EmulatorEvent: EmulatorEvent,
    KEY_ContextEvent: ContextEvent
}


class StateBasedEventFactory(EventFactory):
    """
    factory with customized actions
    """

    def __init__(self, device, app):
        super(StateBasedEventFactory, self).__init__(device, app)

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
        if state is None:
            state = self.device.get_current_state()
        return self.gen_event_based_on_state_wrapper(state)

    def gen_event_based_on_state_wrapper(self, state):
        """
        randomly select a view and click it
        @param state: instance of DeviceState
        @return: event: instance of AppEvent
        """
        from device import DeviceState
        if isinstance(state, DeviceState):
            event = self.gen_event_based_on_state(state)
            assert isinstance(event, AppEvent) or event is None
        else:
            event = UIEvent.get_random_instance(self.device, self.app)
        return event

    def gen_event_based_on_state(self, state):
        return UIEvent.get_random_instance(self.device, self.app)


EVENT_FLAG_STARTED = "+started"
EVENT_FLAG_START_APP = "+start_app"
EVENT_FLAG_STOP_APP = "+stop_app"
EVENT_FLAG_TOUCH = "+touch"


class ManualEventFactory(StateBasedEventFactory):
    """
    manually send events
    droidbot will record the events and states
    """

    def __init__(self, device, app):
        super(ManualEventFactory, self).__init__(device, app)
        self.state_transitions = set()

        self.last_event_flag = ""
        self.last_touched_view_str = None
        self.last_state = None

    def gen_event_based_on_state(self, state):
        """
        generate an event based on current device state
        note: ensure these fields are properly maintained in each transaction:
          last_event_flag, last_touched_view, last_state, exploited_views, state_transitions
        @param state: DeviceState
        @return: AppEvent
        """
        state.save2dir()
        self.save_state_transition(self.last_touched_view_str, self.last_state, state)
        view_to_touch = self.wait_for_manual_event(state)
        self.last_touched_view_str = view_to_touch['view_str']
        self.last_state = state
        return None

    def wait_for_manual_event(self, state):
        """
        wait for user interaction
        @param state: current state of device
        @return: a view in state.views
        """
        self.device.logger.info("Waiting for user input...")

        # implement this using getevent
        # @yzy
        state_dict = state.to_dict()
        touched_view = None

        sp = subprocess.Popen(['adb', '-s', self.device.serial, 'shell', 'getevent', '-lt'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # , bufsize=0)

        onDown = False
        startPosX = -1
        startPosY = -1
        currPosX = -1
        currPosY = -1
        posList = []

        while 1:
            line = sp.stdout.readline()
            if ('ABS_MT_TRACKING_ID' in line) and ('ffffffff' not in line):
                # clear btn_touch down's own positions
                while True:
                    position_line = sp.stdout.readline()
                    if 'ABS_MT_POSITION_X' in position_line:
                        startPosX = int(
                            position_line[position_line.find('ABS_MT_POSITION_X') + len('ABS_MT_POSITION_X'):],
                            16) / 2.0
                    elif 'ABS_MT_POSITION_Y' in position_line:
                        startPosY = int(
                            position_line[position_line.find('ABS_MT_POSITION_Y') + len('ABS_MT_POSITION_Y'):],
                            16) / 2.0
                        posList.append([startPosX, startPosY])
                        break
                print "STARTPOS: %s, %s" % (str(startPosX), str(startPosY))
                currPosX = startPosX
                currPosY = startPosY
                onDown = True

            elif ('ABS_MT_TRACKING_ID' in line) and ('ffffffff' in line) and onDown:
                endPosX = currPosX
                endPosY = currPosY
                while True:
                    position_line = sp.stdout.readline()
                    if 'ABS_MT_POSITION_X' in position_line:
                        endPosX = int(
                            position_line[position_line.find('ABS_MT_POSITION_X') + len('ABS_MT_POSITION_X'):],
                            16) / 2.0
                    elif 'ABS_MT_POSITION_Y' in position_line:
                        endPosY = int(
                            position_line[position_line.find('ABS_MT_POSITION_Y') + len('ABS_MT_POSITION_Y'):],
                            16) / 2.0
                        break
                    elif len(position_line) > 0:
                        posList.append([endPosX, endPosY])
                        break

                print "ENDPOS: %s, %s" % (str(endPosX), str(endPosY))

                onDraw = False
                for point in posList:
                    if (point[0] - startPosX) * (point[0] - startPosX) + \
                                    (point[1] - startPosY) * (point[0] - startPosY) >= 10000:
                        onDraw = True
                        break

                if onDraw == False:
                    for view in state_dict["views"]:
                        print view["bounds"]
                        bounds = view["bounds"]
                        if view["parent"] is None or len(view["children"]) != 0:
                            continue
                        if bounds[0][0] <= startPosX <= bounds[1][0] and \
                                                bounds[0][1] <= startPosY <= bounds[1][1]:
                            touched_view = view
                            break

                    if touched_view is None:
                        print 'no view'
                        touched_view = {"view_str": "UNKNOWN_TOUCH"}
                else:
                    touched_view = {"view_str": "DRAW:%s" % json.dumps(posList)}

                break

            elif 'ABS_MT_POSITION_X' in line:
                currPosX = int(line[line.find('ABS_MT_POSITION_X') + len('ABS_MT_POSITION_X'):], 16) / 2.0
                while True:
                    y_line = sp.stdout.readline()
                    if 'ABS_MT_POSITION_Y' in y_line:
                        currPosY = int(y_line[y_line.find('ABS_MT_POSITION_Y') + len('ABS_MT_POSITION_Y'):], 16) / 2.0
                        posList.append([currPosX, currPosY])
                    break

        sp.kill()

        # touched_view = random.choice(state.views)

        self.device.logger.info("Captured user input: %s" % touched_view['view_str'])
        return touched_view

    def save_state_transition(self, event_str, old_state, new_state):
        """
        save the state transition
        @param event_str: str, representing the event cause the transition
        @param old_state: DeviceState
        @param new_state: DeviceState
        @return:
        """
        if event_str is None or old_state is None or new_state is None:
            return
        if new_state.is_different_from(old_state):
            self.state_transitions.add((event_str, old_state.tag, new_state.tag))

    def dump(self):
        """
        dump the explored_views and state_transitions to file
        @return:
        """
        state_transitions_file = open(os.path.join(self.device.output_dir, "state_transitions.json"), "w")
        json.dump(list(self.state_transitions), state_transitions_file, indent=2)
        state_transitions_file.close()


class UtgDynamicFactory(StateBasedEventFactory):
    """
    record device state during execution
    """

    def __init__(self, device, app):
        super(UtgDynamicFactory, self).__init__(device, app)
        self.explored_views = set()
        self.state_transitions = set()

        self.last_event_flag = ""
        self.last_touched_view_str = None
        self.last_state = None

    def gen_event_based_on_state(self, state):
        """
        generate an event based on current device state
        note: ensure these fields are properly maintained in each transaction:
          last_event_flag, last_touched_view, last_state, exploited_views, state_transitions
        @param state: DeviceState
        @return: AppEvent
        """
        state.save2dir()
        self.save_state_transition(self.last_touched_view_str, self.last_state, state)

        if self.device.is_foreground(self.app):
            # the app is in foreground, clear last_event_flag
            self.last_event_flag = EVENT_FLAG_STARTED
        else:
            number_of_starts = self.last_event_flag.count(EVENT_FLAG_START_APP)
            # if we have tried too many times but still not started, stop droidbot
            if number_of_starts > 5:
                raise StopSendingEventException("The app cannot be started.")
            # if app is not started, try start it
            if self.last_event_flag.endswith(EVENT_FLAG_START_APP):
                # It seems the app stuck at some state, and cannot be started
                # just pass to let viewclient deal with this case
                pass
            else:
                start_app_intent = self.app.get_start_intent()

                self.last_event_flag += EVENT_FLAG_START_APP
                self.last_touched_view_str = None
                self.last_state = state
                return IntentEvent(start_app_intent)

        # select a view to click
        view_to_touch = self.select_a_view(state)

        # if no view can be selected, restart the app
        if view_to_touch is None:
            stop_app_intent = self.app.get_stop_intent()
            self.last_event_flag += EVENT_FLAG_STOP_APP
            self.last_touched_view_str = None
            self.last_state = state
            return IntentEvent(stop_app_intent)

        view_to_touch_str = view_to_touch['view_str']
        if view_to_touch_str.startswith('BACK'):
            result = KeyEvent('BACK')
        else:
            x, y = DeviceState.get_view_center(view_to_touch)
            result = TouchEvent(x, y)

        self.last_event_flag += EVENT_FLAG_TOUCH
        self.last_touched_view_str = view_to_touch_str
        self.last_state = state
        self.save_explored_view(self.last_state, self.last_touched_view_str)
        return result

    def select_a_view(self, state):
        """
        select a view in the view list of given state, let droidbot touch it
        @param state: DeviceState
        @return:
        """
        views = []
        for view in state.views:
            if view['enabled'] == "true" and len(view['children']) == 0 and DeviceState.get_view_size(view) != 0:
                views.append(view)

        random.shuffle(views)

        # add a "BACK" view, consider go back first
        # mock_view_back = {'view_str': 'BACK_%s' % state.foreground_activity}
        # views.insert(0, mock_view_back)

        # first try to find a un-clicked view
        for view in views:
            if (state.foreground_activity, view['view_str']) not in self.explored_views:
                self.device.logger.info("selected an un-clicked view: %s" % view['view_str'])
                return view

        # if all enabled views have been clicked, try jump to another activity by clicking one of state transitions
        random.shuffle(views)
        transition_views = {transition[0] for transition in self.state_transitions}
        for view in views:
            if view['view_str'] in transition_views:
                self.device.logger.info("selected a transition view: %s" % view['view_str'])
                return view

        # no window transition found, just return a random view
        # view = views[0]
        # self.device.logger.info("selected a random view: %s" % view['view_str'])
        # return view

        # DroidBot stuck on current state, return None
        return None

    def save_state_transition(self, event_str, old_state, new_state):
        """
        save the state transition
        @param event_str: str, representing the event cause the transition
        @param old_state: DeviceState
        @param new_state: DeviceState
        @return:
        """
        if event_str is None or old_state is None or new_state is None:
            return
        if new_state.is_different_from(old_state):
            self.state_transitions.add((event_str, old_state.tag, new_state.tag))

    def save_explored_view(self, state, view_str):
        """
        save the explored view
        @param state: DeviceState, where the view located
        @param view_str: str, representing a view
        @return:
        """
        state_activity = state.foreground_activity
        self.explored_views.add((state_activity, view_str))

    def dump(self):
        """
        dump the explored_views and state_transitions to file
        @return:
        """
        explored_views_file = open(os.path.join(self.device.output_dir, "explored_views.json"), "w")
        json.dump(list(self.explored_views), explored_views_file, indent=2)
        explored_views_file.close()

        state_transitions_file = open(os.path.join(self.device.output_dir, "state_transitions.json"), "w")
        json.dump(list(self.state_transitions), state_transitions_file, indent=2)
        state_transitions_file.close()

        from state_transition_graph import TransitionGraph
        utg = TransitionGraph(input_path=self.device.output_dir)
        utg_file = open(os.path.join(self.device.output_dir, "droidbot_UTG.json"), "w")
        json.dump(utg.data, utg_file, indent=2)
        utg_file.close()


class ScriptEventFactory(EventFactory):
    """
    factory which produces events from file
    """

    def __init__(self, device, app, script_dict):
        """
        create a FileEventFactory from a json file
        :param script_dict script path string
        """
        super(ScriptEventFactory, self).__init__(device, app)
        self.script_dict = script_dict
        from droidbot_script import DroidBotScript
        self.script = DroidBotScript(self.script_dict)
        self.script_event_queue = []

        self.default_policy = self.script.default_policy
        self.policy_event_factories = {}
        self.current_policy = None
        self.current_policy_count = 0

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
        # if the previous operation is not finished, continue
        if len(self.script_event_queue) != 0:
            script_event = self.script_event_queue.pop(0)
            return script_event
        if self.current_policy_count > 0:
            self.current_policy_count -= 1
            return self.gen_event_with_policy(self.current_policy, state)

        # if the previous operation is finished, try to get a new operation based on current state
        if state is None:
            state = self.device.get_current_state()
        operation = self.script.get_operation_based_on_state(state)
        if operation is not None:
            self.script_event_queue = list(operation.events)
            self.current_policy = operation.event_policy
            self.current_policy_count = operation.event_count
            return self.generate_event()

        # if current state is not defined in script, use the default policy
        return self.gen_event_with_policy(self.default_policy, state)

    def gen_event_with_policy(self, policy, state):
        if policy not in self.policy_event_factories:
            self.policy_event_factories[policy] =\
                AppEventManager.get_event_factory(policy, self.device, self.app)
        event_factory = self.policy_event_factories[policy]
        return event_factory.generate_event(state)
