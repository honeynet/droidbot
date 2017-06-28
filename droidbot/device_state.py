import os
import subprocess


class DeviceState(object):
    """
    the state of the current device
    """

    def __init__(self, device, view_client_views, foreground_activity, background_services, tag=None,
                 screenshot_path=None):
        self.device = device
        self.view_client_views = view_client_views
        self.foreground_activity = foreground_activity
        self.background_services = background_services
        if tag is None:
            from datetime import datetime
            tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.tag = tag
        self.screenshot_path = screenshot_path
        self.views = self.views2list(view_client_views)
        self.state_str = self.get_state_str()

    def to_dict(self):
        state = {'tag': self.tag,
                 'state_str': self.state_str,
                 'foreground_activity': self.foreground_activity,
                 'background_services': self.background_services,
                 'views': self.views}
        return state

    def to_json(self):
        import json
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def views2list(view_client_views):
        views = []
        if len(view_client_views) == 0:
            return views

        from adapter.viewclient import View
        if isinstance(view_client_views[0], View):
            view2id_map = {}
            id2view_map = {}
            temp_id = 0
            for view in view_client_views:
                view2id_map[view] = temp_id
                id2view_map[temp_id] = view
                temp_id += 1

            for view in view_client_views:
                view_dict = {}
                view_dict['class'] = view.getClass()  # None is possible value
                view_dict['text'] = view.getText()  # None is possible value
                view_dict['resource_id'] = view.getId()  # None is possible value
                view_dict['temp_id'] = view2id_map.get(view)
                view_dict['parent'] = view2id_map.get(view.getParent())  # None is possible value
                view_dict['children'] = [view2id_map.get(view_child) for view_child in view.getChildren()]
                view_dict['enabled'] = view.isEnabled()
                view_dict['focused'] = view.isFocused()
                view_dict['clickable'] = view.isClickable()
                view_dict['bounds'] = view.getBounds()
                view_dict['size'] = "%d*%d" % (view.getWidth(), view.getHeight())
                view_dict['view_str'] = DeviceState.get_view_str(view_dict)
                views.append(view_dict)
        elif isinstance(view_client_views[0], dict):
            for view_dict in view_client_views:
                bounds = [[-1, -1], [-1, -1]]
                bounds[0][0] = view_dict['bounds'][0]
                bounds[0][1] = view_dict['bounds'][1]
                bounds[1][0] = view_dict['bounds'][2]
                bounds[1][1] = view_dict['bounds'][3]
                width = bounds[1][0] - bounds[0][0]
                height = bounds[1][1] - bounds[0][1]
                view_dict['size'] = "%d*%d" % (width, height)
                view_dict['bounds'] = bounds
                resource_id = view_dict['resource_id']
                if resource_id is not None and ":" in resource_id:
                    resource_id = resource_id[(resource_id.find(":") + 1):]
                    view_dict['resource_id'] = resource_id
                view_dict['view_str'] = DeviceState.get_view_str(view_dict)
                views.append(view_dict)
        return views

    def get_state_str(self):
        view_strs = set()
        for view in self.views:
            if 'view_str' in view:
                view_str = view['view_str']
                if view_str is not None and len(view_str) > 0:
                    view_strs.add(view_str)
        state_str = "%s{%s}" % (self.foreground_activity, ",".join(sorted(view_strs)))
        return state_str

    def save2dir(self, output_dir=None):
        try:
            if output_dir is None:
                if self.device.output_dir is None:
                    return
                else:
                    output_dir = os.path.join(self.device.output_dir, "states")
            if not os.path.exists(output_dir):
                os.mkdir(output_dir)
            state_json_file_path = "%s/state_%s.json" % (output_dir, self.tag)
            screenshot_output_path = "%s/screen_%s.png" % (output_dir, self.tag)
            state_json_file = open(state_json_file_path, "w")
            state_json_file.write(self.to_json())
            state_json_file.close()
            subprocess.check_call(["cp", self.screenshot_path, screenshot_output_path])
            # from PIL.Image import Image
            # if isinstance(self.screenshot_path, Image):
            #     self.screenshot_path.save(screenshot_output_path)
        except Exception as e:
            self.device.logger.warning("saving state to dir failed: " + e.message)

    def is_different_from(self, another_state):
        """
        compare this state with another
        @param another_state: DeviceState
        @return: boolean, true if this state is different from other_state
        """
        return self.state_str != another_state.state_str

    @staticmethod
    def get_view_str(view_dict):
        """
        get the unique string which can represent the view
        @param view_dict: dict, element of list device.get_current_state().views
        @return:
        """
        view_str = "[class]%s[resource_id]%s[text]%s[%s,%s,%s,%s]" % \
                   (view_dict['class'] if 'class' in view_dict else 'None',
                    view_dict['resource_id'] if 'resource_id' in view_dict else 'None',
                    view_dict['text'] if 'text' in view_dict else 'None',
                    DeviceState.__key_if_true(view_dict, 'enabled'),
                    DeviceState.__key_if_true(view_dict, 'checked'),
                    DeviceState.__key_if_true(view_dict, 'selected'),
                    DeviceState.__key_if_true(view_dict, 'focused'))
        return view_str

    @staticmethod
    def __key_if_true(view_dict, key):
        return key if (key in view_dict and view_dict[key]) else ""

    @staticmethod
    def get_view_center(view_dict):
        """
        return the center point in a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        return (bounds[0][0] + bounds[1][0]) / 2, (bounds[0][1] + bounds[1][1]) / 2

    @staticmethod
    def get_view_size(view_dict):
        """
        return the size of a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        import math
        return int(math.fabs((bounds[0][0] - bounds[1][0]) * (bounds[0][1] - bounds[1][1])))
