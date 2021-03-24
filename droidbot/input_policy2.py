import logging
import collections
import copy
import logging
import random
import time
import math

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pad_sequence

from .input_event import KeyEvent, IntentEvent, TouchEvent, UIEvent, KillAppEvent
from .input_policy import UtgBasedInputPolicy

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s")
DEBUG = True
ACTION_INEFFECTIVE = 'ineffective'

CLOSER_ACTION_ENCOURAGEMENT = 0.01
RANDOM_EXPLORE_PROB = 0.4
N_ACTIONS_TRAINING = 32

MAX_NUM_STEPS_OUTSIDE = 3
MAX_NUM_STEPS_OUTSIDE_KILL = 5
MAX_NAV_STEPS = 10


class UIEmbedLSTM(nn.Module):
    def __init__(self):
        super().__init__()
        self.text_encoder = TextEncoder(method='bert')
        input_size = 18 + self.text_encoder.embed_size
        embed_size = 100
        output_size = 50
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=int(embed_size/2),
            num_layers=2,
            batch_first=True,
            bidirectional=True
        )
        self.fc = nn.Linear(embed_size, output_size)
        # self.fc = nn.Linear(input_size, output_size)

    def encode_state(self, state, views):
        return torch.stack([self._encode_view(state, view) for view in views])

    def _encode_view(self, state, view):
        # print(view)
        view_children = view['children'] if 'children' in view else []
        is_parent = 1 if len(view_children) > 0 else -1
        view_text = view['text'] if 'text' in view else None
        is_text = 1 if view_text and len(view_text) > 0 else -1
        enabled = 1 if 'enabled' in view and view['enabled'] else -1
        visible = 1 if 'visible' in view and view['visible'] else -1
        clickable = 1 if 'clickable' in view and view['clickable'] else -1
        long_clickable = 1 if 'long_clickable' in view and view['long_clickable'] else -1
        checkable = 1 if 'checkable' in view and view['checkable'] else -1
        checked = 1 if 'checked' in view and view['checked'] else -1
        selected = 1 if 'selected' in view and view['selected'] else -1
        editable = 1 if 'editable' in view and view['editable'] else -1
        is_password = 1 if 'is_password' in view and view['is_password'] else -1
        scrollable = 1 if 'scrollable' in view and view['scrollable'] else -1
        screen_w = state.width
        screen_h = state.height
        [[l,t], [r,b]] = view['bounds'] if 'bounds' in view else [[0,0], [0,0]]
        l, r, t, b = l/screen_w, r/screen_w, t/screen_h, b/screen_h
        view_w = abs(l - r)
        view_h = abs(t - b)
        size = view_w * view_h
        wh_ratio = view_w / (view_h + 0.0001)
        wh_ratio = min(wh_ratio, 10)
        text_emb = self.text_encoder.encode(view_text)
        encoding = np.concatenate([np.array([
            is_parent, is_text, is_password, visible,
            l, r, t, b, size, wh_ratio,
            enabled, checked, selected,
            clickable, long_clickable, checkable, editable, scrollable
        ]), text_emb])
        return torch.Tensor(encoding)

    def forward(self, state_encs):
        state_encs = pad_sequence(state_encs, batch_first=True)
        emb, _ = self.lstm(state_encs)
        return F.normalize(self.fc(emb))
        # return F.normalize(self.fc(x))


class TextEncoder:
    def __init__(self, method='spacy'):
        self.method = method
        self.embed_size = -1
        if method == 'spacy':
            import spacy
            self.nlp = spacy.load("en_core_web_md")
            self.embed_size = 300
        if method == 'bert':
            from transformers import BertTokenizer, BertModel
            from torch.nn import TransformerEncoder, TransformerEncoderLayer
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-multilingual-cased')
            self.text_encoder = BertModel.from_pretrained('bert-base-multilingual-cased')
            self.embed_size = 768

    def encode(self, text):
        if not text:
            return np.zeros(self.embed_size)
        if self.method == 'spacy':
            doc = self.nlp(text)
            return doc.vector
        if self.method == 'bert':
            encoding = self.tokenizer([text], return_tensors='pt', padding=True, truncation=True)
            input_ids = encoding['input_ids']
            attention_mask = encoding['attention_mask']
            text_encoder_out = self.text_encoder(input_ids, attention_mask=attention_mask)
            text_emb = text_encoder_out['pooler_output'][0]
            return text_emb.detach().cpu().numpy()


class BertLayerNorm(nn.Module):
    def __init__(self, hidden_size, eps=1e-5):
        """Construct a layernorm module in the TF style (epsilon inside the square root).
        """
        super(BertLayerNorm, self).__init__()
        self.weight = nn.Parameter(torch.ones(hidden_size))
        self.bias = nn.Parameter(torch.zeros(hidden_size))
        self.variance_epsilon = eps

    def forward(self, x):
        u = x.mean(-1, keepdim=True)
        s = (x - u).pow(2).mean(-1, keepdim=True)
        x = (x - u) / torch.sqrt(s + self.variance_epsilon)
        return self.weight * x + self.bias


class SinusoidalPositionalEncoding(nn.Module):

    def __init__(self, d_model, pos_max=128):
        super().__init__()
        self.d_model = d_model
        self.pos_max = pos_max
        d_model = int(d_model / 4)
        pe = torch.zeros(pos_max, d_model)
        position = torch.arange(0, pos_max).unsqueeze(1)
        div_term = torch.exp((torch.arange(0, d_model, 2, dtype=torch.float) *
                              -(math.log(10000.0) / d_model)))
        pe[:, 0::2] = torch.sin(position.float() * div_term)
        pe[:, 1::2] = torch.cos(position.float() * div_term)
        self.pe = pe

    def forward(self, pos_enc):
        l = pos_enc[:, 0]
        r = pos_enc[:, 1]
        t = pos_enc[:, 2]
        b = pos_enc[:, 3]
        l_emb, r_emb, t_emb, b_emb = self.pe[l], self.pe[r], self.pe[t], self.pe[b]
        pos_emb = torch.cat([l_emb, r_emb, t_emb, b_emb], dim=1)
        # print(f'pos_enc for {i},{j}: wh={w},{h}')
        return pos_emb


class AbsolutePositionalEncoding(nn.Module):
    def __init__(self, d_model, pos_max=128):
        super().__init__()
        self.pos_max = pos_max
        self.d_model = d_model
        nhid = d_model
        self.x_position_embeddings = nn.Embedding(self.pos_max, nhid)
        self.y_position_embeddings = nn.Embedding(self.pos_max, nhid)
        self.h_position_embeddings = nn.Embedding(self.pos_max, nhid)
        self.w_position_embeddings = nn.Embedding(self.pos_max, nhid)

    def forward(self, pos_enc):
        l_emb = self.x_position_embeddings(pos_enc[:, 0])
        r_emb = self.x_position_embeddings(pos_enc[:, 1])
        t_emb = self.y_position_embeddings(pos_enc[:, 2])
        b_emb = self.y_position_embeddings(pos_enc[:, 3])
        w_emb = self.w_position_embeddings(pos_enc[:, 4])
        h_emb = self.h_position_embeddings(pos_enc[:, 5])
        pos_emb = l_emb + r_emb + t_emb + b_emb + w_emb + h_emb
        return pos_emb


class UIEmbedTransformer(nn.Module):

    def __init__(self, nhid=64, nhead=2, nlayers=2, dropout=0.8):
        super().__init__()
        self.model_type = 'Transformer'
        # nhid must be divided by 8 if using sinusoidal positional encoding
        from torch.nn import TransformerEncoder, TransformerEncoderLayer
        self.pos_max = 128
        self.text_encoder = TextEncoder(method='bert')
        dim_feedforward = 256
        encoder_layers = TransformerEncoderLayer(nhid, nhead, dim_feedforward, dropout)
        self.transformer_encoder = TransformerEncoder(encoder_layers, nlayers)
        self.meta2hid = nn.Linear(12, nhid)
        self.text2hid = nn.Linear(self.text_encoder.embed_size, nhid)
        self.pos2hid = AbsolutePositionalEncoding(d_model=nhid, pos_max=self.pos_max)
        self.layer_norm = BertLayerNorm(nhid)
        self.dropout = nn.Dropout(dropout)

    def forward(self, state_encs):
        state_encs, attn_mask = self.encode_state_batch(state_encs)
        output = self.transformer_encoder(state_encs, src_key_padding_mask=attn_mask)
        output = output.permute(1, 0, 2)
        return output

    def encode_state(self, state, views):
        meta_enc = torch.stack([self._encode_view_meta(state, view) for view in views])
        pos_enc = torch.stack([self._encode_view_pos(state, view) for view in views])
        text_enc = torch.stack([self._encode_view_text(state, view) for view in views])
        return meta_enc, pos_enc, text_enc

    def encode_state_batch(self, state_encs):
        embs = []
        for state_enc in state_encs:
            meta_enc, pos_enc, text_enc = state_enc
            # pos_enc = self.pos_encoder(src)
            meta_emb = self.meta2hid(meta_enc)
            pos_emb = self.pos2hid(pos_enc)
            text_emb = self.text2hid(text_enc)
            # emb = torch.cat([meta_emb, pos_emb, text_emb], dim=1)
            emb = meta_emb + pos_emb + text_emb
            emb = self.layer_norm(emb)
            emb = self.dropout(emb)
            embs.append(emb)
        embs_pad = pad_sequence(embs, batch_first=False)
        attn_mask = embs_pad.sum(axis=2).t() == 0
        return embs_pad, attn_mask

    def _encode_view_meta(self, state, view):
        # print(view)
        view_children = view['children'] if 'children' in view else []
        is_parent = 1 if len(view_children) > 0 else -1
        view_text = view['text'] if 'text' in view else None
        is_text = 1 if view_text and len(view_text) > 0 else -1
        enabled = 1 if 'enabled' in view and view['enabled'] else -1
        visible = 1 if 'visible' in view and view['visible'] else -1
        clickable = 1 if 'clickable' in view and view['clickable'] else -1
        long_clickable = 1 if 'long_clickable' in view and view['long_clickable'] else -1
        checkable = 1 if 'checkable' in view and view['checkable'] else -1
        checked = 1 if 'checked' in view and view['checked'] else -1
        selected = 1 if 'selected' in view and view['selected'] else -1
        editable = 1 if 'editable' in view and view['editable'] else -1
        is_password = 1 if 'is_password' in view and view['is_password'] else -1
        scrollable = 1 if 'scrollable' in view and view['scrollable'] else -1
        meta_enc = np.array([
            is_parent, is_text, is_password, visible,
            enabled, checked, selected,
            clickable, long_clickable, checkable, editable, scrollable
        ])
        return torch.Tensor(meta_enc)

    def _encode_view_pos(self, state, view):
        screen_w = state.width
        screen_h = state.height
        [[l,t], [r,b]] = view['bounds'] if 'bounds' in view else [[0,0], [0,0]]
        l, r, t, b = l/screen_w, r/screen_w, t/screen_h, b/screen_h
        if l > r:
            tmp = l
            l = r
            r = tmp
        if t > b:
            tmp = t
            t = b
            b = tmp
        l = max(0, min(1, l))
        r = max(0, min(1, r))
        t = max(0, min(1, t))
        b = max(0, min(1, b))

        pos_max = self.pos_max - 1
        l, r, t, b = int(pos_max*l), int(pos_max*r), int(pos_max*t), int(pos_max*b)
        w = abs(l - r)
        h = abs(t - b)
        return torch.LongTensor(np.array([l, r, t, b, w, h]))

    def _encode_view_text(self, state, view):
        view_text = view['text'] if 'text' in view else None
        emb = self.text_encoder.encode(view_text)
        return torch.Tensor(emb)


class Memory:
    def __init__(self, utg, app):
        self.utg = utg
        self.app = app
        self.known_states = collections.OrderedDict()
        self.known_transitions = collections.OrderedDict()
        self.known_structures = collections.OrderedDict()
        self.model = UIEmbedTransformer()

    def _memorize_state(self, state):
        if state.get_app_activity_depth(self.app) != 0:
            return None
        if state.state_str not in self.known_states:
            views = state.views
            views_str = [view['view_str'] for view in views]
            state_enc = self.model.encode_state(state, views)
            embedder = self.model
            embedder.eval()
            with torch.no_grad():
                # state_encs = self.model.encode_state_batch([state_enc])
                views_emb = self.model.forward([state_enc])
                views_emb = views_emb.detach().cpu()[0]
            self.known_states[state.state_str] = {
                'state': state,
                'views': views,
                'views_str': views_str,
                'state_enc': state_enc,
                'views_emb': views_emb
            }
        return self.known_states[state.state_str]

    def save_transition(self, action, from_state, to_state):
        if not from_state or not to_state:
            return
        from_state_info = self._memorize_state(from_state)
        to_state_info = self._memorize_state(to_state)
        if not isinstance(action, TouchEvent):
            return
        if action.view is None:
            return
        action_str = action.get_event_str(state=from_state)
        if action_str in self.known_transitions and self.known_transitions[action_str]['to_state'] == to_state:
            return
        if from_state_info is None:
            return
        view = action.view
        view_idx = from_state_info['views_str'].index(view['view_str'])
        action_target = ACTION_INEFFECTIVE \
            if from_state.structure_str == to_state.structure_str \
            else to_state.structure_str
        # TODO decide how to represent the effect of an action
        # action_effect = f'{from_state.structure_str}->{action_target}'
        action_effect = action_target
        self.known_transitions[action_str] = {
            'from_state': from_state,
            'to_state': to_state,
            'action': action,
            'view_idx': view_idx,
            'action_effect': action_effect
        }

    def save_structure(self, state):
        structure_str = state.structure_str
        is_new_structure = False
        if structure_str not in self.known_structures:
            self.known_structures[structure_str] = []
            is_new_structure = True
        self.known_structures[structure_str].append(state)
        return is_new_structure

    def _select_transitions_for_training(self, size):
        if len(self.known_transitions) <= size:
            return list(self.known_transitions.keys())
        effect2actions = {}
        for k,v in self.known_transitions.items():
            action_effect = v['action_effect']
            if action_effect not in effect2actions:
                effect2actions[action_effect] = []
            effect2actions[action_effect].append(k)
        action_strs = []
        action_probs = []
        prob_per_effect = 1.0 / len(effect2actions)
        for effect in effect2actions:
            prob_per_action = prob_per_effect / len(effect2actions[effect])
            for action_str in effect2actions[effect]:
                action_strs.append(action_str)
                action_probs.append(prob_per_action)
        action_probs = np.array(action_probs) / sum(action_probs)
        selected_actions = np.random.choice(action_strs, size=size, replace=False, p=action_probs)
        return selected_actions

    def encode_action_pairs(self, action_strs=None):
        if action_strs is None:
            action_strs = list(self.known_transitions.keys())

        state_strs = [self.known_transitions[action_str]['from_state'].state_str for action_str in action_strs]
        state_encs = [self.known_states[state_str]['state_enc'] for state_str in state_strs]
        action_pairs = []
        for i, action_str1 in enumerate(action_strs):
            state_str1 = self.known_transitions[action_str1]['from_state'].state_str
            state_idx1 = state_strs.index(state_str1)
            view_idx1 = self.known_transitions[action_str1]['view_idx']
            for j, action_str2 in enumerate(action_strs[i+1:]):
                state_str2 = self.known_transitions[action_str2]['from_state'].state_str
                state_idx2 = state_strs.index(state_str2)
                view_idx2 = self.known_transitions[action_str2]['view_idx']
                action_effect1 = self.known_transitions[action_str1]['action_effect']
                action_effect2 = self.known_transitions[action_str2]['action_effect']
                # if action_effect1 == ACTION_INEFFECTIVE and action_effect2 == ACTION_INEFFECTIVE:
                #     continue
                effect_same = 1 if action_effect1 == action_effect2 else 0
                action_pairs.append((state_idx1, view_idx1, state_idx2, view_idx2, effect_same))
        return state_encs, action_pairs
    
    def get_known_actions_emb(self):
        actions_emb = []
        for action_str in self.known_transitions:
            action_info = self.known_transitions[action_str]
            state_str = action_info['from_state'].state_str
            view_idx = action_info['view_idx']
            if state_str not in self.known_states:
                continue
            action_emb = self.known_states[state_str]['views_emb'][view_idx]
            actions_emb.append(action_emb)
        return torch.stack(actions_emb) if len(actions_emb) > 0 else None

    @staticmethod
    def action_info_str(action_info):
        state_activity = action_info['from_state'].foreground_activity
        view_sig = action_info['action'].view['signature']
        action_effect = action_info['action_effect']
        return f'{state_activity}-{view_sig}-{action_effect}'

    def train_model(self):
        if len(self.known_transitions.keys()) < 2:
            return

        embedder = self.model
        optimizer = torch.optim.Adam(embedder.parameters(), lr=1e-3)
        n_iterations = 10

        def compute_loss(ele_embed, action_pairs):
            pos_emb_u = []
            pos_emb_v = []
            neg_emb_u = []
            neg_emb_v = []
            for state_idx1, view_idx1, state_idx2, view_idx2, effect_same in action_pairs:
                emb_u = ele_embed[state_idx1, view_idx1]
                emb_v = ele_embed[state_idx2, view_idx2]
                if effect_same:
                    pos_emb_u.append(emb_u)
                    pos_emb_v.append(emb_v)
                else:
                    neg_emb_u.append(emb_u)
                    neg_emb_v.append(emb_v)

            pos_score = 0
            neg_score = 0
            if len(pos_emb_u) > 0 and len(pos_emb_v) > 0:
                pos_emb_u = torch.stack(pos_emb_u)
                pos_emb_v = torch.stack(pos_emb_v)
                pos_score = torch.cosine_similarity(pos_emb_u, pos_emb_v)
                pos_score = F.logsigmoid(pos_score).mean()
            if len(neg_emb_u) > 0 and len(neg_emb_v) > 0:
                neg_emb_u = torch.stack(neg_emb_u)
                neg_emb_v = torch.stack(neg_emb_v)
                neg_score = torch.cosine_similarity(neg_emb_u, neg_emb_v)
                neg_score = F.logsigmoid(-neg_score).mean()
            loss = -pos_score - neg_score
            return loss

        def train():
            embedder.train()
            action_strs = self._select_transitions_for_training(size=N_ACTIONS_TRAINING)
            state_encs, action_pairs = self.encode_action_pairs(action_strs)
            ele_embed = embedder.forward(state_encs)

            loss = compute_loss(ele_embed, action_pairs)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            return loss.item(), len(action_pairs)

        for i in range(n_iterations):
            epoch_start_time = time.time()
            loss, n_pairs = train()
            elapsed = time.time() - epoch_start_time
            print(f'| iter: {i:3d} | time: {elapsed:6.2f}s | #pairs: {n_pairs:6d} | loss: {loss:8.4f}')

        # update embedding
        with torch.no_grad():
            embedder.eval()
            state_encs = [v['state_enc'] for k,v in self.known_states.items()]
            # state_encs_pad = pad_sequence(state_encs, batch_first=True)
            ele_embed = embedder(state_encs)
            ele_embed = ele_embed.detach().cpu()
            for i, (k,v) in enumerate(self.known_states.items()):
                self.known_states[k]['views_emb'] = ele_embed[i]

    def get_unexplored_actions(self, current_state):
        action_strs = set()
        structure_strs = set()
        self._memorize_state(current_state)
        for state_str, state_info in reversed(self.known_states.items()):
            state = state_info['state']
            if state.structure_str in structure_strs:
                continue
            structure_strs.add(state.structure_str)
            for action in state.get_possible_input():
                if not isinstance(action, TouchEvent):
                    continue
                action_str = action.get_event_str(state=state)
                if action_str in action_strs:
                    continue
                if self.utg.is_event_explored(action, state):
                    continue
                action_strs.add(action_str)
                yield state, action

    def get_action_emb(self, state, action):
        state_str = state.state_str
        view_str = action.view['view_str']
        view_idx = self.known_states[state_str]['views_str'].index(view_str)
        action_emb = self.known_states[state_str]['views_emb'][view_idx]
        return action_emb


class MemoryGuidedPolicy(UtgBasedInputPolicy):
    def __init__(self, device, app, random_input):
        super(MemoryGuidedPolicy, self).__init__(device, app, random_input)
        self.logger = logging.getLogger(self.__class__.__name__)

        self.memory = Memory(utg=self.utg, app=self.app)
        self.num_actions_train = 10

        self._nav_steps = []
        self._num_steps_outside = 0

    def generate_event_based_on_utg(self):
        """
        generate an event based on current UTG
        @return: InputEvent
        """
        current_state = self.current_state
        try:
            self.memory.save_transition(self.last_event, self.last_state, current_state)
        except Exception as e:
            self.logger.warning(f'failed to save transition: {e}')
            import traceback
            traceback.print_exc()
        if self.action_count % self.num_actions_train == 0:
            self.memory.train_model()
        # self.logger.info(f'we have {len(self.memory.known_transitions)} transitions now')

        if self.last_event is not None:
            self.last_event.log_lines = self.parse_log_lines()
        # interested_apis = self.monitor.get_interested_api()
        # self.monitor.check_env()
        self.logger.debug("Current state: %s" % current_state.state_str)

        nav_action = self.navigate(current_state)
        if nav_action:
            return nav_action
        self._nav_steps = []  # if navigation fails, stop navigating

        if current_state.get_app_activity_depth(self.app) < 0:
            # If the app is not in the activity stack
            start_app_intent = self.app.get_start_intent()
            self.logger.info("starting app")
            return IntentEvent(intent=start_app_intent)
        elif current_state.get_app_activity_depth(self.app) > 0:
            # If the app is in activity stack but is not in foreground
            self._num_steps_outside += 1
            if self._num_steps_outside > MAX_NUM_STEPS_OUTSIDE:
                # If the app has not been in foreground for too long, try to go back
                if self._num_steps_outside > MAX_NUM_STEPS_OUTSIDE_KILL:
                    stop_app_intent = self.app.get_stop_intent()
                    go_back_event = IntentEvent(stop_app_intent)
                else:
                    start_app_intent = self.app.get_start_intent()
                    go_back_event = IntentEvent(intent=start_app_intent)
                self.logger.info("going back to the app")
                return go_back_event
        else:
            # If the app is in foreground
            self._num_steps_outside = 0

        # if it is a new structure, try to go back first
        is_structure_new = self.memory.save_structure(current_state)
        if is_structure_new:
            self.logger.info("it is a new structure, going back")
            return KeyEvent(name="BACK")

        if self.action_count >= self.num_actions_train \
                and len(self._nav_steps) == 0 \
                and np.random.uniform() > RANDOM_EXPLORE_PROB:
            (target_state, target_action), candidates = self.pick_target(current_state)
            if target_state:
                # perform target action or navigate to target action
                if target_state.state_str == current_state.state_str:
                    self.logger.info(f"executing action selected from {len(candidates)} candidates")
                    return target_action
                self._nav_steps = self.get_shortest_nav_steps(current_state, target_state, target_action)
                nav_action = self.navigate(current_state)
                if nav_action:
                    return nav_action
        self._nav_steps = []  # if navigation fails, stop navigating

        self.logger.info("trying random action")
        possible_events = current_state.get_possible_input()
        possible_events.append(KeyEvent(name="BACK"))
        random.shuffle(possible_events)
        return possible_events[0]

    def pick_target(self, current_state):
        state_action_pairs = list(self.memory.get_unexplored_actions(current_state))
        best_target = None, None
        best_score = -np.inf
        known_actions_emb = self.memory.get_known_actions_emb()
        if known_actions_emb is None:
            return best_target, state_action_pairs
        if DEBUG:
            known_actions_str = [Memory.action_info_str(v) for k, v in self.memory.known_transitions.items()]
        scores = []
        for i, (state, action) in enumerate(state_action_pairs):
            action_emb = self.memory.get_action_emb(state, action)
            similarities = torch.cosine_similarity(action_emb.repeat((known_actions_emb.size(0), 1)), known_actions_emb)
            max_sim, max_sim_idx = similarities.max(0)
            score = -max_sim
            if state.state_str == current_state.state_str:
                score += CLOSER_ACTION_ENCOURAGEMENT        # encourage actions in current state
            if DEBUG:
                action_info_str = f'{state.foreground_activity}-{action.view["signature"]}'
                scores.append((i, score, action_info_str, similarities, action_emb))
            if score > best_score:
                best_score = score
                best_target = state, action
        return best_target, state_action_pairs

    def navigate(self, current_state):
        if self._nav_steps and len(self._nav_steps) > 0:
            nav_state, nav_action = self._nav_steps[0]
            self._nav_steps = self._nav_steps[1:]
            nav_action_ = self._get_nav_action(current_state, nav_state, nav_action)
            if nav_action_:
                self.logger.info(f"navigating, {len(self._nav_steps)} steps left")
                return nav_action_
            else:
                self.logger.warning(f"navigation failed")
                self.utg.remove_transition(self.last_event, self.last_state, nav_state)

    def _get_nav_action(self, current_state, nav_state, nav_action):
        # get the action similar to nav_action in current state
        try:
            if current_state.structure_str != nav_state.structure_str:
                return None
            if not isinstance(nav_action, UIEvent):
                return nav_action
            nav_view = nav_action.view
            nav_view_idx = nav_state.views.index(nav_view)
            new_view = current_state.views[nav_view_idx]
            new_action = copy.deepcopy(nav_action)
            new_action.view = new_view
            return new_action
        except Exception as e:
            self.logger.warning(f'exception during _get_nav_action: {e}')
            return nav_action

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

    def get_shortest_nav_steps(self, current_state, target_state, target_action):
        normal_nav_steps = self.utg.get_G2_nav_steps(current_state, target_state)
        restart_nav_steps = self.utg.get_G2_nav_steps(self.utg.first_state, target_state)
        normal_nav_steps_len = len(normal_nav_steps) if normal_nav_steps else MAX_NAV_STEPS
        restart_nav_steps_len = len(restart_nav_steps) + 1 if restart_nav_steps else MAX_NAV_STEPS
        if normal_nav_steps_len >= MAX_NAV_STEPS and restart_nav_steps_len >= MAX_NAV_STEPS:
            self.logger.warning(f'cannot find a path to {target_state.structure_str} {target_state.foreground_activity}')
            target_state_str = target_state.state_str
            # forget the unavailable state
            self.memory.known_states.pop(target_state_str)
            action_strs_to_remove = []
            for action_str in self.memory.known_transitions:
                action_from_state = self.memory.known_transitions[action_str]['from_state']
                action_to_state = self.memory.known_transitions[action_str]['to_state']
                if action_from_state.state_str == target_state_str or action_to_state.state_str == target_state_str:
                    action_strs_to_remove.append(action_str)
            for action_str in action_strs_to_remove:
                self.memory.known_transitions.pop(action_str)
            return None
        # elif normal_nav_steps_len > restart_nav_steps_len:  # prefer shortest path
        elif normal_nav_steps_len >= MAX_NAV_STEPS:  # prefer normal navigation
            nav_steps = [(current_state, KillAppEvent(app=self.app))] + restart_nav_steps
        else:
            nav_steps = normal_nav_steps
        return nav_steps + [(target_state, target_action)]


# class InputPolicy2(object):
#     """
#     This class is responsible for generating events to stimulate more app behaviour
#     """
#
#     def __init__(self, device, app, random_input=True):
#         self.logger = logging.getLogger(self.__class__.__name__)
#         self.device = device
#         self.app = app
#         self.random_input = random_input
#         self.utg = UTG(device=device, app=app, random_input=random_input)
#         self.input_manager = None
#         self.action_count = 0
#         self.state = None
#
#     @property
#     def enabled(self):
#         if self.input_manager is None:
#             return False
#         return self.input_manager.enabled and self.action_count < self.input_manager.event_count
#
#     def perform_action(self, action):
#         self.input_manager.add_event(action)
#         self.action_count += 1
#
#     def start(self, input_manager):
#         """
#         start producing actions
#         :param input_manager: instance of InputManager
#         """
#         self.input_manager = input_manager
#         self.action_count = 0
#
#         episode_i = 0
#         while self.enabled:
#             try:
#                 episode_i += 1
#                 self.device.send_intent(self.app.get_stop_intent())
#                 self.device.key_press('HOME')
#                 self.device.send_intent(self.app.get_start_intent())
#                 self.state = self.device.current_state()
#                 self.start_episode()
#             except KeyboardInterrupt:
#                 break
#             except Exception as e:
#                 self.logger.warning(f"exception during episode {episode_i}: {e}")
#                 import traceback
#                 traceback.print_exc()
#                 continue
#
#     @abstractmethod
#     def start_episode(self):
#         pass

