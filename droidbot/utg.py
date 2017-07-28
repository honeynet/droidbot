import networkx as nx
import logging
import json
import os


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
        self.__output_utg()

    def add_node(self, state):
        if not state:
            return
        if state.state_str not in self.G.nodes():
            state.save2dir()
            self.G.add_node(state.state_str, state=state)

    def __output_utg(self):
        """
        Output current UTG to a dot file
        :return: 
        """
        if not self.device.output_dir:
            return
        utg_file_path = os.path.join(self.device.output_dir, "utg.json")
        utg_file = open(utg_file_path, "w")
        utg_nodes = []
        utg_edges = []
        for state_str in self.G.nodes():
            state = self.G.node[state_str]['state']
            utg_node = {
                "id": state_str,
                "shape": "image",
                "image": state.screenshot_path,
                "label": state.foreground_activity
            }
            utg_nodes.append(utg_node)
        for state_transition in self.G.edges():
            from_state = state_transition[0]
            to_state = state_transition[1]
            # events = self.G[from_state][to_state]['events']
            # for event in events:
            #     event_id = "%s: %s->%s" % (event.get_event_str(from_state), from_state, to_state)
            utg_edge = {
                "from": from_state,
                "to": to_state
            }
            utg_edges.append(utg_edge)
        utg = {
            "nodes": utg_nodes,
            "edges": utg_edges
        }
        json.dump(utg, utg_file, indent=2)
        utg_file.close()

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
        try:
            states = nx.shortest_path(G=self.G, source=current_state.state_str, target=target_state.state_str)
            if not isinstance(states, list) or len(states) < 2:
                self.logger.warning("Error getting path from %s to %s" % (current_state.state_str, target_state.state_str))
            start_state = states[0]
            for state in states[1:]:
                edge = self.G[start_state][state]
                edge_events = edge['events']
                path_events.append(edge_events[0])
                start_state = state
        except:
            self.logger.warning("Cannot find a path from %s to %s" % (current_state.state_str, target_state.state_str))
        return path_events
