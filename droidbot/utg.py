import networkx as nx
import logging


class UTG(object):
    """
    UI transition graph
    """

    def __init__(self, device, app):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.device = device
        self.app = app

        self.G = nx.DiGraph()

        self.effective_events = set()
        self.ineffective_events = set()
        self.explored_states = set()

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
        return event_str in self.effective_events or event_str in self.ineffective_events

    def is_state_explored(self, state):
        if state.state_str in self.explored_states:
            return True
        for possible_event in state.get_possible_input():
            if not self.is_event_explored(possible_event, state):
                return False
        self.explored_states.add(state.state_str)
        return True

    def get_reachable_states(self, current_state):
        reachable_states = []
        for target_state_str in nx.descendants(self.G, current_state.state_str):
            target_state = self.G.node[target_state_str]['state']
            reachable_states.append(target_state)
        return reachable_states

    def get_event_path(self, current_state, target_state):
        path_events = []
        states = nx.shortest_path(G=self.G, source=current_state.state_str, target=target_state.state_str)
        if not isinstance(states, list) or len(states) < 2:
            self.logger.warning("Error getting path from %s to %s" % (current_state.state_str, target_state.state_str))
        start_state = states[0]
        for state in states[1:]:
            edge = self.G[start_state][state]
            edge_events = edge['events']
            path_events.append(edge_events[0])
            start_state = state
        return path_events
