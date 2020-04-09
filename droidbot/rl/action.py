import numpy as np
from .configs import *


class Action:
    """
    An action that the RL agent can send to the device, including the following fields
        Name	        Meaning
        action_type     Probability of each action type, including gesture, intent, key
        gesture_type    Probability of gesture types, including CLICK, LONG_CLICK, SCROLL_UP, SCROLL_DOWN
        gesture_pos	    Probability of gesture position <x, y>
        broadcast       Probability of sending each broadcast. The full list is at input_event.POSSIBLE_BROADCASTS
        key	            Probability of pressing each key, including BACK, HOME, VOLUME_UP, VOLUME_DOWN
    """
    @staticmethod
    def get_event_generator(action):
        return EventGenerator(action)

    @staticmethod
    def get_space():
        from gym import spaces
        return spaces.Dict(dict(
            action_type=spaces.Box(low=0, high=1, dtype=np.float, shape=(len(ACTION_TYPES),)),
            gesture_type=spaces.Box(low=0, high=1, dtype=np.float, shape=(len(GESTURE_TYPES),)),
            gesture_pos=spaces.Box(low=0, high=1, dtype=np.float, shape=(SCREEN_H, SCREEN_W)),
            APIs=spaces.MultiBinary(len(INTERESTED_APIS))
        ))


class EventGenerator:
    def __init__(self, action):
        self.action = action

    def gen_event(self):
        """
        TODO Generate an event based on the action given by the agent.
        The generated event can be directly sent to the device.
        :return: an event sampled based on the given action representation
        """
        return None

