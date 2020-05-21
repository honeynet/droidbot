import numpy as np
from .configs import *
from droidbot.input_event import *

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
            broadcast=spaces.Box(low=0, high=1, dtype=np.float, shape=(len(POSSIBLE_BROADCASTS),)),
            key=spaces.Box(low=0, high=1, dtype=np.float, shape=(len(POSSIBLE_KEYS),))
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
        action_types = self.action['action_type']
        action_val = np.unravel_index(action_types.argmax(), action_types.shape)

        if ACTION_TYPES[action_val[0]] == 'gesture':
            # print("action: gesture")
            gesture_types = self.action['gesture_type']
            gesture_val = np.unravel_index(gesture_types.argmax(), gesture_types.shape)

            gesture_pos = self.action['gesture_pos']
            x_pos, y_pos = np.unravel_index(gesture_pos.argmax(), gesture_pos.shape)
            if GESTURE_TYPES[gesture_val[0]] == "touch":
                # print("action: click")
                event = TouchEvent(x_pos, y_pos)
            elif GESTURE_TYPES[gesture_val[0]] == "long_touch":
                # print("long click")
                event = LongTouchEvent(x=x_pos, y=y_pos, duration=2000)
            elif GESTURE_TYPES[gesture_val[0]] == "scroll_up":
                # print("scroll up")
                event = ScrollEvent(x=x_pos, y=y_pos, direction="UP")
            elif GESTURE_TYPES[gesture_val[0]] == "scroll_down":
                # print("scroll down")
                event = ScrollEvent(x=x_pos, y=y_pos, direction="DOWN")
        elif ACTION_TYPES[action_val[0]] == 'intent':
            # print("action: intent")
            intent_list = self.action["broadcast"]
            intent_type = "adb shell am start -a " + POSSIBLE_BROADCASTS[np.unravel_index(intent_list.argmax(), intent_list.shape)[0]]
            event = IntentEvent(intent=intent_type)
        elif ACTION_TYPES[action_val[0]] == 'key':
            # print("action key press")
            key_press_list = self.action['key']
            key_press_type = POSSIBLE_KEYS[np.unravel_index(key_press_list.argmax(), key_press_list.shape)[0]]
            event = KeyEvent(name=key_press_type)

        return event

