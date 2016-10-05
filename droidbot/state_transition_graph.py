import json
import os


class TransitionGraph(object):
    """
    The UI state transition graph (UTG) of an app
    in a UTG, each node n is a UI state, and each edge e is a UI event.
    """
    def __init__(self, input_path=None, similarity_threshold=None, compare_keys=None, state_offset=None):
        self.unique_states = {}
        self.state_name_map = {}
        self.input_path = input_path
        self.state_path = self.input_path + "/states/" if self.input_path is not None else None
        self.event_file_path = self.input_path + "/droidbot_event.json" if self.input_path is not None else None

        self.similarity_threshold = 0.8 if similarity_threshold is None else similarity_threshold
        self.compare_keys = ["class", "package", "view_str", "content-desc", "resource-id"] \
            if compare_keys is None else compare_keys

        self.state_offset = 0 if state_offset is None else state_offset

        if self.input_path is not None:
            self.data = self.build()

    def build(self):
        self._init_data()
        self.remove_duplicate_state()

        return self.events

    def to_json(self):
        return json.dumps(self.data, indent=2)

    def _init_data(self):
        if self.input_path is None:
            return

        # read event data
        event_file = open(self.event_file_path)
        event_data = json.loads(event_file.read())
        self.events = []
        for i in range(0, len(event_data), 1):
            self.events.append(self.get_event(event_data[i], i + 1))
        event_file.close()

        if self.state_offset < 0:
            self.events = self.events[-self.state_offset:]

        # read device state data
        self.state_files = ["start", "homescreen"]
        self.state_json = [{}, {}]
        for root, _, states in os.walk(self.state_path):
            for state in sorted(states):
                if state[-4:] == "json":
                    if self.state_offset > 0:
                        self.state_offset -= 1
                        continue
                    self.state_files.append(state[-22: -5])
                    self.state_json.append(json.loads(open(root + "/" + state).read()))
        self.state_files.append("end")
        self.state_json.append({})

        # if their lengths are not equal,
        if len(self.state_files) - 1 < len(self.events):
            for i in range(0, len(self.events) - len(self.state_files) + 1, 1):
                self.events.pop()
        else:
            for i in range(0, len(self.state_files) - 1 - len(self.events), 1):
                self.state_files.pop()
                self.state_json.pop()

        # init edges data
        for i in range(0, len(self.events), 1):
            self.events[i]["startState"] = self.state_files[i]
            self.events[i]["endState"] = self.state_files[i + 1]

    def remove_duplicate_state(self):
        # remove duplicate state
        for i in range(0, len(self.state_files), 1):
            state = self.state_json[i]
            state_name = self.state_files[i]
            if state == {}:
                self.unique_states[state_name] = state
                self.state_name_map[state_name] = state_name
                continue

            _dup = False
            for _state_name, _state in self.unique_states.items():
                if self.is_duplicate_state(state, _state):
                    _dup = True
                    self.state_name_map[state_name] = _state_name
                    break
            if not _dup:
                self.unique_states[state_name] = state
                self.state_name_map[state_name] = state_name

        # set the nodes of an edge, and add clicked view information
        for i in range(0, len(self.events), 1):
            self.events[i]["startState"] = self.state_name_map[self.state_files[i]]
            self.events[i]["endState"] = self.state_name_map[self.state_files[i + 1]]
            self.find_view(i)

    def find_view(self, i):
        if self.events[i]["eventType"] != "touchEvent":
            return

        self.events[i]["event"] = []

        views = {}

        temp_data = []
        id_to_view_map = {}
        view = None
        x = self.events[i]["x"]
        y = self.events[i]["y"]
        if "views" in self.state_json[i].keys():
            for v in self.state_json[i]["views"]:
                id_to_view_map[v["temp_id"]] = v
                _bound = v['bounds']
                if _bound[0][0] <= x <= _bound[1][0] and _bound[0][1] <= y <= _bound[1][1]:
                    views[v["temp_id"]] = {"parent": v["parent"], "target": 1}

            if len(views) == 0:
                print "error when matching point (" + str(x) + "," + str(y) + ") to state "\
                      + self.state_files[i] + ", id = " + str(i)
            else:
                for temp_id in views.keys():
                    if views[temp_id]["parent"] is not None and views[temp_id]["parent"] in views.keys():
                        views[views[temp_id]["parent"]]["target"] = 0

                for temp_id in views.keys():
                    if views[temp_id]["target"] == 1:
                        temp_data.append(id_to_view_map[temp_id])

                view = temp_data[0]
                _area = (view["bounds"][1][0] - view["bounds"][1][0]) *\
                        (view["bounds"][1][1] - view["bounds"][0][1])
                for _view in temp_data:
                    if (_view["bounds"][1][0] - _view["bounds"][1][0]) *\
                            (_view["bounds"][1][1] - _view["bounds"][0][1]) < _area:
                        view = _view
                        _area = (_view["bounds"][1][0] - _view["bounds"][1][0]) *\
                                (_view["bounds"][1][1] - _view["bounds"][0][1])

        if view is not None:
            self.events[i]["event"].append(view)

    @staticmethod
    def get_event(event, idx):
        result = {}
        if event["event_type"] == "key":
            result["eventType"] = "keyEvent"
            result["event"] = "KEYCODE_" + event["name"]
        elif event["event_type"] == "touch" or event["event_type"] == "long_touch" or event["event_type"] == "drag":
            result["eventType"] = "touchEvent"

            if event["event_type"] == "touch" or event["event_type"] == "long_touch":
                result["x"] = int(event["x"])
                result["y"] = int(event["y"])
            elif event["event_type"] == "drag":
                result["x"] = int(event["start_x"])
                result["y"] = int(event["start_y"])

        elif event["event_type"] == "intent":
            result["eventType"] = "startActivity"
            result["event"] = event["intent"][event["intent"].rfind(' ') + 1:]

        result["id"] = idx
        return result

    def compare_view(self, view1, view2):
        flag = True
        for key in view1.keys():
            if key in self.compare_keys and ((key not in view2) or view1[key] != view2[key]):
                flag = False
                break

        if not flag:
            return flag

        for key in view2.keys():
            if key in self.compare_keys and ((key not in view1) or view1[key] != view2[key]):
                flag = False
                break
        return flag

    def _traverse(self, small_view_map, large_view_map, view_id):
        cnt = 1 if self.compare_view(small_view_map[view_id], large_view_map[view_id]) else 0

        for child in small_view_map[view_id]["children"]:
            cnt += self._traverse(small_view_map, large_view_map, child)
        return cnt

    def is_duplicate_state(self, state1, state2):
        if state2 == {} or state1["foreground_activity"] != state2["foreground_activity"]:
            return False

        small_state = state1 if len(state1["views"]) < len(state2["views"]) else state2
        large_state = state1 if len(state1["views"]) >= len(state2["views"]) else state2

        assert isinstance(small_state, dict) and isinstance(large_state, dict)
        assert "views" in small_state and "views" in large_state

        small_view_map = {}
        for view in small_state["views"]:
            small_view_map[view["temp_id"]] = view
        large_view_map = {}
        for view in large_state["views"]:
            large_view_map[view["temp_id"]] = view

        if self._traverse(small_view_map, large_view_map, 0) >= len(small_state["views"]) * self.similarity_threshold:
            return True
        return False


if __name__ == '__main__':
    graph = TransitionGraph(input_path="~/droidbot_samples/com.devexpert.weather_droidbot")

    data = graph.to_json()
