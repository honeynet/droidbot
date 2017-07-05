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

    def add_transition(self, event, old_state, new_state):
        self.add_node(old_state)
        self.add_node(new_state)

        # make sure the states are not None
        if not old_state or not new_state:
            return

        if (old_state.state_str, new_state.state_str) not in self.G.edges():
            self.G.add_edge(old_state.state_str, new_state.state_str, events=[])

        self.G[old_state.state_str][new_state.state_str]['events'].append(event)

    def add_node(self, state):
        if not state:
            return
        if state.state_str not in self.G.nodes():
            state.save2dir()
            self.G.add_node(state.state_str, state=state)

