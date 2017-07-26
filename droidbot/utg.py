import networkx as nx
from input_event import UIEvent


class UTG(object):
    """
    UI transition graph
    """

    def __init__(self, device, app):
        self.device = device
        self.app = app

        self.G = nx.Graph()
        self.effective_events = set()
        self.ineffective_events = set()

    def add_transition(self, event, old_state, new_state):
        self.add_node(old_state)
        self.add_node(new_state)

        # make sure the states are not None
        if not old_state or not new_state:
            return

        event_str = event.get_event_str(old_state)

        if old_state.state_str == new_state.state_str:
            self.ineffective_events.add(event_str)
            return

        self.effective_events.add(event_str)
        if (old_state.state_str, new_state.state_str) not in self.G.edges():
            self.G.add_edge(old_state.state_str, new_state.state_str, events=[])
        self.G[old_state.state_str][new_state.state_str]['events'].append(event)

    def add_node(self, state):
        if not state:
            return
        if state.state_str not in self.G.nodes():
            state.save2dir()
            self.G.add_node(state.state_str, state=state)

    def is_event_explored(self, event, state):
        event_str = event.get_event_str(state)

