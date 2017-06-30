class UTG(object):
    """
    UI transition graph
    """

    def __init__(self, device, app):
        self.device = device
        self.app = app

        self.node2states = {}
        self.edge2events = {}

    def add_transition(self, event_str, old_state, new_state):
        old_node = self.state_to_node(old_state)
        new_node = self.state_to_node(new_state)
        self.add_edge(event_str, old_node, new_node)

    def state_to_node(self, state):
        if state is None:
            state_str = "none"
            state_tag = "none"
        else:
            state_str = state.get_state_str()
            state_tag = state.tag
        if state_str not in self.node2states:
            self.node2states[state_str] = []
        self.node2states[state_str].append(state_tag)
        return state_str

    def add_edge(self, event_str, old_node, new_node):
        if old_node == new_node:
            return
        edge_str = "<%s> --> <%s>" % (old_node, new_node)
        if edge_str not in self.edge2events:
            self.edge2events[edge_str] = []
        self.edge2events[edge_str].append(event_str)
