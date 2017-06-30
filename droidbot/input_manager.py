import json
import logging
import os
import subprocess
import time
from threading import Timer

from input_event import EventLog, KeyEvent, IntentEvent

POLICY_NONE = "none"
POLICY_MONKEY = "monkey"
POLICY_BFS = "bfs"
POLICY_DFS = "dfs"
POLICY_MANUAL = "manual"

DEFAULT_POLICY = POLICY_DFS
DEFAULT_EVENT_INTERVAL = 1
DEFAULT_EVENT_COUNT = 1000
DEFAULT_TIMEOUT = -1

START_RETRY_THRESHOLD = 20


class UnknownInputException(Exception):
    pass


class InputManager(object):
    """
    This class manages all events to send during app running
    """

    def __init__(self, device, app, event_policy, no_shuffle,
                 event_count, event_interval, event_duration,
                 script_path=None, profiling_method=None):
        """
        manage input event sent to the target device
        :param device: instance of Device
        :param app: instance of App
        :param event_policy: policy of generating events, string
        :return:
        """
        self.logger = logging.getLogger('InputEventManager')
        self.enabled = True

        self.device = device
        self.app = app
        self.policy = event_policy
        self.no_shuffle = no_shuffle
        self.events = []
        self.event_factory = None
        self.script = None
        self.event_count = event_count
        self.event_interval = event_interval
        self.event_duration = event_duration
        self.monkey = None
        self.timer = None

        if script_path is not None:
            f = open(script_path, 'r')
            script_dict = json.load(f)
            from input_script import DroidBotScript
            self.script = DroidBotScript(script_dict)

        self.event_factory = self.get_event_factory(device, app)
        self.profiling_method = profiling_method

    def get_event_factory(self, device, app):
        policy = self.policy
        if policy == POLICY_NONE:
            event_factory = None
        elif policy == POLICY_MONKEY:
            event_factory = None
        elif policy == POLICY_BFS:
            event_factory = UtgBfsFactory(device, app, self.no_shuffle)
        elif policy == POLICY_DFS:
            event_factory = UtgDfsFactory(device, app, self.no_shuffle)
        elif policy == POLICY_MANUAL:
            event_factory = ManualEventFactory(device, app)
        else:
            event_factory = None
        if isinstance(event_factory, StateBasedEventFactory):
            event_factory.script = self.script
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

        event_log = EventLog(self.device, self.app, event, self.profiling_method)
        if self.profiling_method is not None:
            event_log.start_profiling()
        self.device.send_event(event)
        time.sleep(self.event_interval)
        if self.profiling_method is not None:
            event_log.stop_profiling()
        event_log.save2dir()

    def dump(self):
        """
        dump the event information to files
        :return:
        """
        if self.device.output_dir is None:
            return
        event_log_file = open(os.path.join(self.device.output_dir, "droidbot_event.json"), "w")
        event_array = []
        for event in self.events:
            event_array.append(event.to_dict())
        json.dump(event_array, event_log_file, indent=2)
        event_log_file.close()
        self.logger.debug("Event log saved to droidbot_event.json")
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

        if self.event_duration > 0:
            self.timer = Timer(self.event_duration, self.stop)
            self.timer.start()

        try:
            if self.event_factory is not None:
                self.event_factory.start(self)
            elif self.policy == POLICY_NONE:
                self.device.start_app(self.app)
                if self.event_count == 0:
                    return
                while self.enabled:
                    time.sleep(1)
            elif self.policy == POLICY_MONKEY:
                throttle = self.event_interval * 1000
                monkey_cmd = "adb -s %s shell monkey %s --ignore-crashes --ignore-security-exceptions" \
                             " --throttle %d %d" % \
                             (self.device.serial,
                              "" if self.app.get_package_name() is None else "-p " + self.app.get_package_name(),
                              throttle,
                              self.event_count)
                self.monkey = subprocess.Popen(monkey_cmd.split(),
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
                while self.enabled:
                    time.sleep(1)
            elif self.policy == POLICY_MANUAL:
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
        self.logger.info("Finish sending events")
        self.dump()

    def stop(self):
        """
        stop sending event
        """
        if self.monkey:
            self.monkey.terminate()
            self.monkey = None
            pid = self.device.get_app_pid("com.android.commands.monkey")
            if pid is not None:
                self.device.shell("kill -9 %d" % pid)
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
