import sys
import json
import logging
import random
import numpy as np
from abc import abstractmethod

from .input_event import InputEvent, KeyEvent, IntentEvent, TouchEvent, ManualEvent, SetTextEvent
from .input_policy import UtgBasedInputPolicy
from .utg import UTG
from .monitor import Monitor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s")

# Policy taxanomy
POLICY_MEMORY_GUIDED = "memory_guided"


class InputPolicy2(object):
    """
    This class is responsible for generating events to stimulate more app behaviour
    """

    def __init__(self, device, app, random_input=True):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.device = device
        self.app = app
        self.random_input = random_input
        self.utg = UTG(device=device, app=app, random_input=random_input)
        self.input_manager = None
        self.action_count = 0
        self.state = None

    @property
    def enabled(self):
        if self.input_manager is None:
            return False
        return self.input_manager.enabled and self.action_count < self.input_manager.event_count

    def perform_action(self, action):
        self.input_manager.add_event(action)
        self.action_count += 1

    def start(self, input_manager):
        """
        start producing actions
        :param input_manager: instance of InputManager
        """
        self.input_manager = input_manager
        self.action_count = 0
        
        episode_i = 0
        while self.enabled:
            try:
                episode_i += 1
                self.device.send_intent(self.app.get_stop_intent())
                self.device.key_press('HOME')
                self.device.send_intent(self.app.get_start_intent())
                self.state = self.device.current_state()
                self.start_episode()
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.warning(f"exception during episode {episode_i}: {e}")
                import traceback
                traceback.print_exc()
                continue

    @abstractmethod
    def start_episode(self):
        pass


class Memory:
    def __init__(self, utg):
        self.utg = utg
        self.model = None

    def train_model(self):
        pass

    def get_unexplored_actions(self):
        pass

    def get_action_novelty(self):
        pass


# Max number of steps outside the app
MAX_NUM_STEPS_OUTSIDE = 3
MAX_NUM_STEPS_OUTSIDE_KILL = 5


class MemoryGuidedPolicy(UtgBasedInputPolicy):
    def __init__(self, device, app, random_input):
        super(MemoryGuidedPolicy, self).__init__(device, app, random_input)
        self.logger = logging.getLogger(self.__class__.__name__)

        self.random_explore_prob = 1.0
        self.__nav_target = None
        self.__nav_num_steps = -1

        self.__num_steps_outside = 0
        self.__missing_states = set()

        # self.monitor = Monitor()
        # self.monitor.serial = self.device.serial
        # self.monitor.packageName = self.app.get_package_name()
        # self.monitor.set_up()

    def generate_event_based_on_utg(self):
        """
        generate an event based on current UTG
        @return: InputEvent
        """
        current_state = self.current_state
        if self.last_event is not None:
            self.last_event.log_lines = self.parse_log_lines()
        # interested_apis = self.monitor.get_interested_api()
        # self.monitor.check_env()
        self.logger.info("Current state: %s" % current_state.state_str)
        if current_state.state_str in self.__missing_states:
            self.__missing_states.remove(current_state.state_str)

        if current_state.get_app_activity_depth(self.app) < 0:
            # If the app is not in the activity stack
            start_app_intent = self.app.get_start_intent()
            self.logger.info("Starting app")
            return IntentEvent(intent=start_app_intent)
        elif current_state.get_app_activity_depth(self.app) > 0:
            # If the app is in activity stack but is not in foreground
            self.__num_steps_outside += 1
            if self.__num_steps_outside > MAX_NUM_STEPS_OUTSIDE:
                # If the app has not been in foreground for too long, try to go back
                if self.__num_steps_outside > MAX_NUM_STEPS_OUTSIDE_KILL:
                    stop_app_intent = self.app.get_stop_intent()
                    go_back_event = IntentEvent(stop_app_intent)
                else:
                    start_app_intent = self.app.get_start_intent()
                    go_back_event = IntentEvent(intent=start_app_intent)
                self.logger.info("Going back to the app")
                return go_back_event
        else:
            # If the app is in foreground
            self.__num_steps_outside = 0

        if np.random.uniform() > self.random_explore_prob:
            target_action = self.pick_interesting_action(current_state)

        self.logger.info("Trying random action")
        possible_events = current_state.get_possible_input()
        possible_events.append(KeyEvent(name="BACK"))
        random.shuffle(possible_events)
        return possible_events[0]

    def parse_log_lines(self):
        log_lines = self.device.logcat.get_recent_lines()
        filtered_lines = []
        app_pid = self.device.get_app_pid(self.app)
        # print(f'current app_pid: {app_pid}')
        for line in log_lines:
            try:
                seps = line.split()
                if int(seps[2]) == app_pid:
                    filtered_lines.append(line)
                    print(f'    {line}')
            except:
                pass
        return filtered_lines

    def pick_interesting_action(self, current_state):
        state_action_pairs = []
        possible_events = current_state.get_possible_input()
        random.shuffle(possible_events)

        # If there is an unexplored event, try the event first
        for input_event in possible_events:
            if not self.utg.is_event_explored(event=input_event, state=current_state):
                self.logger.info("Trying an unexplored event.")
                return input_event

        target_state = self.__get_nav_target(current_state)
        if target_state:
            event_path = self.utg.get_event_path(current_state=current_state, target_state=target_state)
            if event_path and len(event_path) > 0:
                self.logger.info("Navigating to %s, %d steps left." % (target_state.state_str, len(event_path)))
                return event_path[0]

    def __get_nav_target(self, current_state):
        # If last event is a navigation event
        if self.__nav_target and self.__event_trace.endswith(EVENT_FLAG_NAVIGATE):
            event_path = self.utg.get_event_path(current_state=current_state, target_state=self.__nav_target)
            if event_path and 0 < len(event_path) <= self.__nav_num_steps:
                # If last navigation was successful, use current nav target
                self.__nav_num_steps = len(event_path)
                return self.__nav_target
            else:
                # If last navigation was failed, add nav target to missing states
                self.__missing_states.add(self.__nav_target.state_str)

        reachable_states = self.utg.get_reachable_states(current_state)
        if self.random_input:
            random.shuffle(reachable_states)

        for state in reachable_states:
            # Only consider foreground states
            if state.get_app_activity_depth(self.app) != 0:
                continue
            # Do not consider missing states
            if state.state_str in self.__missing_states:
                continue
            # Do not consider explored states
            if self.utg.is_state_explored(state):
                continue
            self.__nav_target = state
            event_path = self.utg.get_event_path(current_state=current_state, target_state=self.__nav_target)
            if len(event_path) > 0:
                self.__nav_num_steps = len(event_path)
                return state

        self.__nav_target = None
        self.__nav_num_steps = -1
        return None

