import argparse
import logging
import os
import sys
import random
import time
from datetime import datetime
import gym
from gym import spaces, logger
from gym.utils import seeding
import numpy as np
from droidbot import Device, App
from droidbot.rl.observation import Observation
from droidbot.rl.action import Action
from droidbot import monitor
from droidbot.rl.RL_test import DQN

class TestEnv(gym.Env):
    """
    Description:
        An app under test is running in an Android device.
        The agent will observe:
            1. the UI
            2. the current process status, e.g. listening broadcast receivers,
                recently executed APIs, recently printed logs, etc.
        The agent can interact with the device by:
            1. sending a gesture
            2. sending a broadcast intent
            3. pressing a key
        The goal is to trigger as many sensitive behaviors in the app as possible in one episode.

    Observation: defined in observation.py

    Action: defined in action.py

    Reward:
        Reward is 1 for every sensitive behavior detected.
        A sensitive behavior is uniquely identified based on the API name (and the stack trace?).

    Starting State:
        All initial observations are obtained right after the app is installed and started.

    Episode Termination:
        Step limit is exceeded.
        Timeout.
    """

    metadata = {
        'episode.step_limit': 200,          # maximum number of steps in an episode
        'episode.timeout': 600,             # maximum duration of an episode
        'step.n_events': 1,                 # number of events per step
        'step.wait': 0,                     # time in seconds to wait after each input event
    }

    def __init__(self, apk_dir, device_serial=None, output_dir='output'):
        self.logger = logging.getLogger('TestEnv')
        self.observation_space = Observation.get_space()
        self.action_space = Action.get_space()

        self.seed_ = self.seed()
        self.viewer = None
        # add by wangsonghe
        self.current_app = None
        self.monitor_thread = None

        self.device = Device(device_serial=device_serial, output_dir=output_dir)
        self.apk_files = self._get_apk_files(apk_dir)
        self.output_dir = output_dir

    def seed(self, seed=None):
        self.np_random, seed = seeding.np_random(seed)
        return [seed]

    def reset(self, app_idx=None):
        """
        reset the current environment by starting the app on the device
        :return: the initial observation
        """
        # make sure the device is connected
        self.device.wait_for_device()

        self._close_episode()

        # get a random app as the current app
        if app_idx is None:
            app_idx = self.np_random.randint(0, len(self.apk_files))
        self.current_app = App(self.apk_files[app_idx])
        self.executed_APIs = []
        self.sensitive_behaviors = []
        self.n_steps = 0
        self.start_time = datetime.now()
        self.running = True
        self.observation = Observation(self.device, self.current_app)

        #wsh
        # install the current app
        self.device.install_app(self.current_app)

        import threading
        self.monitor_thread = threading.Thread(target=self._monitor_APIs)
        self.monitor_thread.start()

        # start the current app on the device
        self.device.start_app(self.current_app)
        time.sleep(3)
        self.device.droidbot_app.connect()

        # get current observation
        return self.observation.observe(self)

    def render(self, mode='human'):
        if mode == 'human':
            from gym.envs.classic_control import rendering
            if self.viewer is None:
                self.viewer = rendering.SimpleImageViewer()
                print(self.device.get_current_state().to_dict())
            #self.viewer.imshow(self.device.get_current_state())
            return self.viewer.isopen

    def step(self, action):
        n_events = self.metadata['step.n_events']
        n_existing_sensitive_behaviors = len(self.sensitive_behaviors)
        event_generator = Action.get_event_generator(action)
        for i in range(n_events):
            event = event_generator.gen_event()
            self.device.send_event(event)
            time.sleep(self.metadata['step.wait'])
        obs = self.observation.observe(self)
        self.executed_APIs = [] # reset interested_apis list
        time.sleep(2) #wait for monitor
        reward = len(self.sensitive_behaviors) - n_existing_sensitive_behaviors
        done = False
        if self.n_steps > self.metadata['episode.step_limit']:
            done = True
        elif (datetime.now() - self.start_time).total_seconds() > self.metadata['episode.timeout']:
            done = True
        info = {}   # put any useful information in this dict
        return obs, reward, done, info

    def close(self):
        self.reset()
        self.device.disconnect()
        pass

    def _get_apk_files(self, apk_dir):
        apk_files = []
        for dir_path, dir_names, file_names in os.walk(apk_dir):
            for file_name in file_names:
                if file_name.lower().endswith('.apk'):
                    apk_files.append(os.path.join(dir_path, file_name))
        return apk_files

    def _close_episode(self):
        # uninstall the current app
        self.running = False
        if self.current_app is not None:
            self.device.uninstall_app(self.current_app)
        if self.monitor_thread is not None:
            # wait for the monitor thread to finish
            time.sleep(1)

    def _monitor_APIs(self):
        # TODO @Songhe monitor the app and maintain self.executed_APIs and self.sensitive_behaviors
        self.monitor = monitor.Monitor()
        self.monitor.serial = self.device.serial
        self.monitor.packageName = self.current_app.get_package_name()
        self.monitor.set_up()
        while self.running:
            self.monitor.check_env()
            time.sleep(5)
            self.sensitive_behaviors += self.monitor.get_sensitive_api()
            self.executed_APIs = self.monitor.get_interested_api()
            pass

        self.monitor.stop()


def parse_args():
    """
    Parse command line input
    :return:
    """
    parser = argparse.ArgumentParser(description="DroidBot RL environment.")

    parser.add_argument("-a", action="store", dest="apk_dir", required=True,
                        help="The directory of apps to test")
    parser.add_argument("-d", action="store", dest="device_serial", required=False, default=None,
                        help="The serial number of target device (use `adb devices` to find)")
    parser.add_argument("-o", action="store", dest="output_dir",
                        help="directory of output")

    args, unknown = parser.parse_known_args()
    return args


def main():
    args = parse_args()
    env = TestEnv(apk_dir=args.apk_dir, device_serial=args.device_serial)
    env.reset()
    for _ in range(100):
        # env.render()
        env.step(env.action_space.sample())  # take a random action
    env.close()
    # dqn_agent = DQN(env, time_steps=4)
    # dqn_agent.train(max_episodes=50)


if __name__ == '__main__':
    main()

