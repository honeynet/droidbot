import numpy as np
from .configs import *
import cv2, os
from PIL import Image

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
        # self.screen_img = device.take_screenshot()
        # self.ui_state = device.get_current_state()
        self.listening_broadcasts = self._encode_receivers(app.possible_broadcasts)
        self.requested_permissions = self._encode_permissions(app.permissions)



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
        Observation.screen_img = env.device.take_screenshot()
        return {
            'UI': Observation._encode_UI(Observation),
            'permissions': env.observation.requested_permissions,
            'receivers': env.observation.listening_broadcasts,
            'APIs': Observation._encode_APIs(Observation, env)
        }

    def _encode_UI(self):
        # return the h*w*c representation of the current user interface
        img = cv2.imread(self.screen_img)
        return img

    def _encode_permissions(self, permissions):
        # return the 1-D vector representation of app permissions
        perms = np.zeros(len(INTERESTED_PERMISSIONS))
        for p in permissions:
            p_temp = p.split('.')[-1]
            if p_temp in INTERESTED_PERMISSIONS:
                index = INTERESTED_PERMISSIONS.index(p_temp)
                perms[index] = 1
        # self.requested_permissions =
        return perms

    def _encode_receivers(self, broadcast_receivers):
        # return the 1-D vector representation of app permissions
        receivers = np.zeros(len(INTERESTED_BROADCASTS))
        for r in broadcast_receivers:
            r_temp = r.action.split('.')[-1]
            if r_temp in INTERESTED_BROADCASTS:
                index = INTERESTED_BROADCASTS.index(r_temp)
                receivers[index] = 1
        # self.listening_broadcasts = receivers
        return receivers

    def _encode_APIs(self, env):
        # return the 1-D vector representation of recently invoked APIs
        apis = np.zeros(len(INTERESTED_APIS))
        for a in env.executed_APIs:
            if a in INTERESTED_APIS:
                index = INTERESTED_APIS.index(a)
                apis[index] = 1
        return apis



