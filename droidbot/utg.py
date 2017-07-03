class UTG(object):
    """
    UI transition graph
    """

    def __init__(self, device, app):
        self.device = device
        self.app = app

        self.node2states = {}
        self.edge2events = {}

    def add_transition(self, event, old_state, new_state):
        if old_state:
            self.add_node(old_state)
        if new_state:
            self.add_node(new_state)
        if not event or not old_state or not new_state:
            return

    def add_node(self, state):
        pass
