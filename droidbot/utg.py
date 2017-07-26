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

        self.__exploration_target = None

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
        for possible_event in state.get_possible_input():
            if not self.is_event_explored(possible_event, state):
                return False
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

    def __get_exploration_target(self, current_state):
        if self.__exploration_target and self.__exploration_target.state_str != current_state.state_str:
            if self.__exploration_target.state_str in nx.descendants(self.G, current_state.state_str):
                return self.__exploration_target
        reachable_states = self.get_reachable_states(current_state)
        for reachable_state in reachable_states:
            # Do not consider un-related states
            if reachable_state.get_app_activity_depth(self.app) < 0:
                pass
            # Do not consider explored states
            if self.is_state_explored(reachable_state):
                pass
            self.__exploration_target = reachable_state
            self.logger.info("Exploration target is changed to " + reachable_state.state_str)
            return reachable_state

    def get_exploration_event(self, current_state):
        # Get all possible input events
        possible_events = current_state.get_possible_input()

        # If there is an unexplored event, try the event first
        for input_event in possible_events:
            if not self.is_event_explored(event=input_event, state=current_state):
                return input_event

        # If all events in this state had been explored, try navigate to a state with an unexplored event
        exploration_target = self.__get_exploration_target(current_state)
        if not exploration_target:
            return None

        event_path = self.get_event_path(current_state=current_state, target_state=exploration_target)
        if event_path and len(event_path) > 0:
            return event_path[0]
