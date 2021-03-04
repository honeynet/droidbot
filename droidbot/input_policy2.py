import sys
import json
import logging
import random
import collections
import numpy as np
from abc import abstractmethod

from .input_event import InputEvent, KeyEvent, IntentEvent, TouchEvent, ManualEvent, SetTextEvent
from .input_policy import UtgBasedInputPolicy
from .device_state import DeviceState
from .utg import UTG

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
        self.model = self._build_model()
        self.known_states = collections.OrderedDict()
        self.known_transitions = collections.OrderedDict()
        self.known_similar_actions = []
        import spacy
        self.nlp = spacy.load("en_core_web_md")

    def _build_model(self, embed_size=200):
        import torch
        return torch.nn.LSTM(
            input_size=input_size,
            hidden_size=int(embed_size/2),
            num_layers=1,
            batch_first=True,
            bidirectional=True
        )

    def _memorize_state(self, state):
        if state.state_str not in self.known_states:
            views = state.views
            views_str = [view['view_str'] for view in views]
            views_enc = np.array([self._encode_view(view) for view in views])
            import torch
            embedder = self.model
            embedder.eval()
            with torch.no_grad():
                views_emb = self.model(torch.Tensor(views_enc).expand_dims(0)).cpu().numpy()[0]
            self.known_states[state.state_str] = {
                'state': state,
                'views': views,
                'views_str': views_str,
                'views_enc': views_enc,
                'views_emb': views_emb
            }
        return self.known_states[state.state_str]

    def _encode_view(self, view):
        print(view)
        return np.zeros(300)
        # is_parent
        # is_image
        # is_text
        # clickable
        # long_clickable
        # checkable
        # editable
        # scrollable
        # size
        # wh_ratio
        # text
        # encoding = [is_parent, is_image, is_text, clickable, long_clickable, checkable, editable, scrollable, size, wh_ratio]
    
    def _update_known_transitions(self):
        for from_state, action, to_state in self.utg.iter_transitions():
            if not isinstance(action, TouchEvent):
                continue
            if action.view is None:
                continue
            action_str = action.get_event_str(state=from_state)
            if action_str in self.known_transitions:
                continue
            state_info = self._memorize_state(from_state)
            view = action.view
            view_idx = state_info['views_str'].index(view['view_str'])
            action_effect = f'{from_state.structure_str}->{to_state.structure_str}'
            self.known_transitions[action_str] = {
                'from_state': from_state,
                'to_state': to_state,
                'action': action,
                'view_idx': view_idx,
                'action_effect': action_effect
            }
            for previous_action_str in self.known_transitions:
                previous_action_effect = self.known_transitions[previous_action_str]['action_effect']
                if action_effect == previous_action_effect:
                    self.known_similar_actions.append((action_str, previous_action_str))
    
    def get_known_actions_emb(self):
        actions_emb = []
        for action_str in self.known_transitions:
            action_info = self.known_transitions[action_str]
            state_str = action_info['from_state'].state_str
            view_idx = action_info['view_idx']
            action_emb = self.known_states[state_str]['views_emb'][view_idx]
            actions_emb.append(action_emb)
        return actions_emb

    def train_model(self):
        self._update_known_transitions()
        embedder = self.model
        optimizer = torch.optim.Adam(embedder.parameters(), lr=1e-3)
        log_per_batch = 10
        n_epochs = 5

        def compute_loss(ele_embed, ele_P):
            n_tree_ele = ele_embed.size(1)
            embed_size = ele_embed.size(-1)
            emb_u = []
            emb_v = []
            for pair_idx in range(ele_P.size(0)):
                emb_u.append(ele_embed[ele_P[pair_idx, 0], ele_P[pair_idx, 1]])
                emb_v.append(ele_embed[ele_P[pair_idx, 2], ele_P[pair_idx, 3]])
            emb_u = torch.stack(emb_u)
            emb_v = torch.stack(emb_v)
            # print(f'{emb_u.size()} {emb_v.size()} {ele_embed.size()}')

            emb_all = ele_embed.reshape((-1, embed_size))

            n_nodes = emb_all.size(0)
            neg_u = torch.LongTensor(np.random.choice(n_nodes, emb_u.size(0)))
            neg_v = torch.LongTensor(np.random.choice(n_nodes, emb_v.size(0)))

            emb_neg_u = emb_all[neg_u]
            emb_neg_v = emb_all[neg_v]
            # print(f'{emb_u.size()} {emb_v.size()} {emb_neg_v.size()}')

            score = torch.cosine_similarity(emb_u, emb_v)
            score = F.logsigmoid(score)

            neg_score = torch.cosine_similarity(emb_u, emb_neg_v) + torch.cosine_similarity(emb_neg_u, emb_v)
            neg_score = -neg_score
            neg_score = F.logsigmoid(neg_score)

            loss = -score - neg_score
            return loss

        def train():
            total_loss = 0
            total_pairs = 0
            embedder.train()
            for i, (ele_X, ele_P) in enumerate(train_dl):
                # Forward pass: Compute predicted y by passing x to the model
                ele_embed, _ = embedder(ele_X)
                
                loss = compute_loss(ele_embed, ele_P)
                loss_mean = torch.mean(loss)
                loss_sum = torch.sum(loss)
                total_loss += loss_sum.item()
                total_pairs += ele_P.size(0)
                
                # Zero gradients, perform a backward pass, and update the weights.
                optimizer.zero_grad()
                loss_mean.backward()
                optimizer.step()
            return total_loss, total_pairs

        for epoch in range(n_epochs):
            epoch_start_time = time.time()
            total_loss, total_pairs = train()
            avg_loss = total_loss / total_pairs
            elapsed = time.time() - epoch_start_time
            print(f'| epoch: {epoch:3d} | time: {elapsed:8.2f}s | #pairs: {total_pairs:6d} | loss: {avg_loss:8.4f}')
        
    def get_unexplored_actions(self, current_state):
        state_action_pairs = []
        action_strs = []
        self._memorize_state(current_state)
        for action in current_state.get_possible_input():
            if not isinstance(action, TouchEvent):
                continue
            action_str = action.get_event_str(state=current_state)
            if action_str in action_strs:
                continue
            if self.utg.is_event_explored(action, current_state):
                continue
            action_strs.append(action_str)
            state_action_pairs.append((current_state, action))
        for state, action in self.utg.iter_state_events():
            if not isinstance(action, TouchEvent):
                continue
            action_str = action.get_event_str(state=state)
            if action_str in action_strs:
                continue
            if self.utg.is_event_explored(action, state):
                continue
            action_strs.append(action_str)
            state_action_pairs.append((state, action))
        return state_action_pairs

    def get_action_emb(self, state, action):
        state_str = state.state_str
        view_str = action.view['view_str']
        view_idx = self.known_states[state_str]['views_str'].index(view_str)
        action_emb = self.known_states[state_str]['views_emb'][view_idx]
        return action_emb


# Max number of steps outside the app
MAX_NUM_STEPS_OUTSIDE = 3
MAX_NUM_STEPS_OUTSIDE_KILL = 5


class MemoryGuidedPolicy(UtgBasedInputPolicy):
    def __init__(self, device, app, random_input):
        super(MemoryGuidedPolicy, self).__init__(device, app, random_input)
        self.logger = logging.getLogger(self.__class__.__name__)

        self.random_explore_prob = 1.0
        self.memory = Memory(utg=self.utg)

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
            target_state_action = self.pick_target_action(current_state)
            # TODO perform target action or navigate to target action

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
            except:
                pass
        return filtered_lines

    def pick_target_action(self, current_state):
        state_action_pairs = self.memory.get_unexplored_actions(current_state)
        best_state_action = None, None
        score = 0
        for state, action in state_action_pairs:
            action_emb = self.memory.get_action_emb(state, action)
            dist, ind = self.memory.action_emb_btree.query(action_emb)
            if dist > score:
                score = dist
                best_state_action = state, action
        return best_state_action

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

