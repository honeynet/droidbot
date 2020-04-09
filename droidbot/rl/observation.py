import numpy as np
from .configs import *


class Observation:
    """
    The observation of current device and app state, including the following fields:
        Name	        Meaning
        UI              The current user interface, represented as an h*w*c image
        receivers       The broadcasts that the app is listening (one-hot encoding)
        permissions     The permissions that the app requested (one-hot encoding)
        APIs            The APIs that the app executed since last action (one-hot encoding)
    """
    def __init__(self, device, app):
        self.screen_img = device.take_screenshot()
        self.ui_state = device.get_current_state()
        self.listening_broadcasts = app.possible_broadcasts
        self.requested_permissions = app.permissions

    @staticmethod
    def get_space():
        from gym import spaces
        return spaces.Dict(dict(
            UI=spaces.Box(low=0, high=1, dtype=np.float, shape=(SCREEN_H, SCREEN_W, 3)),
            permissions=spaces.MultiBinary(len(INTERESTED_PERMISSIONS)),
            receivers=spaces.MultiBinary(len(INTERESTED_BROADCASTS)),
            APIs=spaces.MultiBinary(len(INTERESTED_APIS))
        ))

    @staticmethod
    def observe(env):
        # TODO implement this
        return Observation.get_space().sample()
        # return {
        #     'UI': self._encode_UI(),
        #     'permissions': self._encode_permissions(),
        #     'receivers': self._encode_receivers(),
        #     'APIs': self._encode_APIs()
        # }

    def _encode_UI(self):
        # return the h*w*c representation of the current user interface
        return None

    def _encode_permissions(self):
        # return the 1-D vector representation of app permissions
        return None

    def _encode_receivers(self):
        # return the 1-D vector representation of app permissions
        return None

    def _encode_APIs(self):
        # return the 1-D vector representation of recently invoked APIs
        return None
