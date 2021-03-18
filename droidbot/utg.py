import logging
import json
import os
import random
import datetime
import networkx as nx


class UTG(object):
    """
    UI transition graph
    """

    def __init__(self, device, app, random_input):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.device = device
        self.app = app
        self.random_input = random_input

        self.G = nx.DiGraph()
        self.G2 = nx.DiGraph()  # graph with same-structure states clustered

        self.transitions = []
        self.effective_event_strs = set()
        self.ineffective_event_strs = set()
        self.explored_state_strs = set()
        self.reached_state_strs = set()
        self.reached_activities = set()

        self.first_state = None
        self.last_state = None

        self.start_time = datetime.datetime.now()

    @property
    def first_state_str(self):
        return self.first_state.state_str if self.first_state else None

    @property
    def last_state_str(self):
        return self.last_state.state_str if self.last_state else None

    @property
    def effective_event_count(self):
        return len(self.effective_event_strs)

    @property
    def num_transitions(self):
        return len(self.transitions)

    def add_transition(self, event, old_state, new_state):
        self.add_node(old_state)
        self.add_node(new_state)

        # make sure the states are not None
        if not old_state or not new_state:
            return

        event_str = event.get_event_str(old_state)
        self.transitions.append((old_state, event, new_state))

        if old_state.state_str == new_state.state_str:
            self.ineffective_event_strs.add(event_str)
            # delete the transitions including the event from utg
            for new_state_str in self.G[old_state.state_str]:
                if event_str in self.G[old_state.state_str][new_state_str]["events"]:
                    self.G[old_state.state_str][new_state_str]["events"].pop(event_str)
            if event_str in self.effective_event_strs:
                self.effective_event_strs.remove(event_str)
            return

        self.effective_event_strs.add(event_str)

        if (old_state.state_str, new_state.state_str) not in self.G.edges():
            self.G.add_edge(old_state.state_str, new_state.state_str, events={})
        self.G[old_state.state_str][new_state.state_str]["events"][event_str] = {
            "event": event,
            "id": self.effective_event_count
        }

        if (old_state.structure_str, new_state.structure_str) not in self.G2.edges():
            self.G2.add_edge(old_state.structure_str, new_state.structure_str, events={})
        self.G2[old_state.structure_str][new_state.structure_str]["events"][event_str] = {
            "event": event,
            "id": self.effective_event_count
        }

        self.last_state = new_state
        self.__output_utg()

    def remove_transition(self, event, old_state, new_state):
        event_str = event.get_event_str(old_state)
        if (old_state.state_str, new_state.state_str) in self.G.edges():
            events = self.G[old_state.state_str][new_state.state_str]["events"]
            if event_str in events.keys():
                events.pop(event_str)
            if len(events) == 0:
                self.G.remove_edge(old_state.state_str, new_state.state_str)
        if (old_state.structure_str, new_state.structure_str) in self.G2.edges():
            events = self.G2[old_state.structure_str][new_state.structure_str]["events"]
            if event_str in events.keys():
                events.pop(event_str)
            if len(events) == 0:
                self.G2.remove_edge(old_state.structure_str, new_state.structure_str)

    def add_node(self, state):
        if not state:
            return
        if state.state_str not in self.G.nodes():
            state.save2dir()
            self.G.add_node(state.state_str, state=state)
            if self.first_state is None:
                self.first_state = state

        if state.structure_str not in self.G2.nodes():
            self.G2.add_node(state.structure_str, states=[])
        self.G2.nodes[state.structure_str]['states'].append(state)

        if state.foreground_activity.startswith(self.app.package_name):
            self.reached_activities.add(state.foreground_activity)

    def __output_utg(self):
        """
        Output current UTG to a js file
        """
        if not self.device.output_dir:
            return

        def list_to_html_table(dict_data):
            table = "<table class=\"table\">\n"
            for (key, value) in dict_data:
                table += "<tr><th>%s</th><td>%s</td></tr>\n" % (key, value)
            table += "</table>"
            return table

        utg_file_path = os.path.join(self.device.output_dir, "utg.js")
        utg_file = open(utg_file_path, "w")
        utg_nodes = []
        utg_edges = []
        for state_str in self.G.nodes():
            state = self.G.nodes[state_str]["state"]
            package_name = state.foreground_activity.split("/")[0]
            activity_name = state.foreground_activity.split("/")[1]
            short_activity_name = activity_name.split(".")[-1]

            state_desc = list_to_html_table([
                ("package", package_name),
                ("activity", activity_name),
                ("state_str", state.state_str),
                ("structure_str", state.structure_str)
            ])

            utg_node = {
                "id": state_str,
                "shape": "image",
                "image": os.path.relpath(state.screenshot_path, self.device.output_dir),
                "label": short_activity_name,
                # "group": state.foreground_activity,
                "package": package_name,
                "activity": activity_name,
                "state_str": state_str,
                "structure_str": state.structure_str,
                "title": state_desc,
                "content": "\n".join([package_name, activity_name, state.state_str, state.search_content])
            }

            if state.state_str == self.first_state_str:
                utg_node["label"] += "\n<FIRST>"
                utg_node["font"] = "14px Arial red"
            if state.state_str == self.last_state_str:
                utg_node["label"] += "\n<LAST>"
                utg_node["font"] = "14px Arial red"

            utg_nodes.append(utg_node)

        for state_transition in self.G.edges():
            from_state = state_transition[0]
            to_state = state_transition[1]

            events = self.G[from_state][to_state]["events"]
            event_short_descs = []
            event_list = []

            for event_str, event_info in sorted(iter(events.items()), key=lambda x: x[1]["id"]):
                event_short_descs.append((event_info["id"], event_str))
                if self.device.adapters[self.device.minicap]:
                    view_images = ["views/view_" + view["view_str"] + ".jpg"
                                   for view in event_info["event"].get_views()]
                else:
                    view_images = ["views/view_" + view["view_str"] + ".png"
                                   for view in event_info["event"].get_views()]
                event_list.append({
                    "event_str": event_str,
                    "event_id": event_info["id"],
                    "event_type": event_info["event"].event_type,
                    "view_images": view_images
                })

            utg_edge = {
                "from": from_state,
                "to": to_state,
                "id": from_state + "-->" + to_state,
                "title": list_to_html_table(event_short_descs),
                "label": ", ".join([str(x["event_id"]) for x in event_list]),
                "events": event_list
            }

            # # Highlight last transition
            # if state_transition == self.last_transition:
            #     utg_edge["color"] = "red"

            utg_edges.append(utg_edge)

        utg = {
            "nodes": utg_nodes,
            "edges": utg_edges,

            "num_nodes": len(utg_nodes),
            "num_edges": len(utg_edges),
            "num_effective_events": len(self.effective_event_strs),
            "num_reached_activities": len(self.reached_activities),
            "test_date": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "time_spent": (datetime.datetime.now() - self.start_time).total_seconds(),
            "num_transitions": self.num_transitions,

            "device_serial": self.device.serial,
            "device_model_number": self.device.get_model_number(),
            "device_sdk_version": self.device.get_sdk_version(),

            "app_sha256": self.app.hashes[2],
            "app_package": self.app.package_name,
            "app_main_activity": self.app.main_activity,
            "app_num_total_activities": len(self.app.activities),
        }

        utg_json = json.dumps(utg, indent=2)
        utg_file.write("var utg = \n")
        utg_file.write(utg_json)
        utg_file.close()

    def is_event_explored(self, event, state):
        event_str = event.get_event_str(state)
        return event_str in self.effective_event_strs or event_str in self.ineffective_event_strs

    def is_state_explored(self, state):
        if state.state_str in self.explored_state_strs:
            return True
        for possible_event in state.get_possible_input():
            if not self.is_event_explored(possible_event, state):
                return False
        self.explored_state_strs.add(state.state_str)
        return True

    def is_state_reached(self, state):
        if state.state_str in self.reached_state_strs:
            return True
        self.reached_state_strs.add(state.state_str)
        return False

    def get_reachable_states(self, current_state):
        reachable_states = []
        for target_state_str in nx.descendants(self.G, current_state.state_str):
            target_state = self.G.nodes[target_state_str]["state"]
            reachable_states.append(target_state)
        return reachable_states

    def get_navigation_steps(self, from_state, to_state):
        if from_state is None or to_state is None:
            return None
        try:
            steps = []
            from_state_str = from_state.state_str
            to_state_str = to_state.state_str
            state_strs = nx.shortest_path(G=self.G, source=from_state_str, target=to_state_str)
            if not isinstance(state_strs, list) or len(state_strs) < 2:
                self.logger.warning(f"Error getting path from {from_state_str} to {to_state_str}")
            start_state_str = state_strs[0]
            for state_str in state_strs[1:]:
                edge = self.G[start_state_str][state_str]
                edge_event_strs = list(edge["events"].keys())
                if self.random_input:
                    random.shuffle(edge_event_strs)
                start_state = self.G.nodes[start_state_str]['state']
                event = edge["events"][edge_event_strs[0]]["event"]
                steps.append((start_state, event))
                start_state_str = state_str
            return steps
        except Exception as e:
            print(e)
            self.logger.warning(f"Cannot find a path from {from_state.state_str} to {to_state.state_str}")
            return None

    # def get_simplified_nav_steps(self, from_state, to_state):
    #     nav_steps = self.get_navigation_steps(from_state, to_state)
    #     if nav_steps is None:
    #         return None
    #     simple_nav_steps = []
    #     last_state, last_action = nav_steps[-1]
    #     for state, action in nav_steps:
    #         if state.structure_str == last_state.structure_str:
    #             simple_nav_steps.append((state, last_action))
    #             break
    #         simple_nav_steps.append((state, action))
    #     return simple_nav_steps

    def get_G2_nav_steps(self, from_state, to_state):
        if from_state is None or to_state is None:
            return None
        from_state_str = from_state.structure_str
        to_state_str = to_state.structure_str
        try:
            nav_steps = []
            state_strs = nx.shortest_path(G=self.G2, source=from_state_str, target=to_state_str)
            if not isinstance(state_strs, list) or len(state_strs) < 2:
                return None
            start_state_str = state_strs[0]
            for state_str in state_strs[1:]:
                edge = self.G2[start_state_str][state_str]
                edge_event_strs = list(edge["events"].keys())
                start_state = random.choice(self.G2.nodes[start_state_str]['states'])
                event_str = random.choice(edge_event_strs)
                event = edge["events"][event_str]["event"]
                nav_steps.append((start_state, event))
                start_state_str = state_str
            if nav_steps is None:
                return None
            # return nav_steps
            # simplify the path
            simple_nav_steps = []
            last_state, last_action = nav_steps[-1]
            for state, action in nav_steps:
                if state.structure_str == last_state.structure_str:
                    simple_nav_steps.append((state, last_action))
                    break
                simple_nav_steps.append((state, action))
            return simple_nav_steps
        except Exception as e:
            print(e)
            return None

