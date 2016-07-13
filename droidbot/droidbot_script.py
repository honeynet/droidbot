# DroidBotScript
# This file contains the definition of DroidBotScript
# DroidBotScript is a domain-specific language, which defines how DroidBot interacts with target app
import re
import logging
from app_event import AppEvent
from droidbot import DroidBotException

VIEW_ID = '<view_id>'
STATE_ID = '<state_id>'
OPERATION_ID = '<operation_id>'
DEFAULT_ID = 'default'
INTEGER_VAL = 0
REGEX_VAL = r'<regex>'
EVENT_POLICY_VAL = '<event_policy>'
EVENT_TYPE_VAL = '<event_type>'
IDENTIFIER_RE = re.compile(r'^[^\d\W]\w*\Z', re.UNICODE)


class DroidBotScript(object):
    """
    DroidBotScript is a DSL which defines how DroidBot interacts with target app
    """
    script_grammar = {
        'views': {
            VIEW_ID: ViewSelector
        },
        'states': {
            STATE_ID: StateSelector
        },
        'operations': {
            OPERATION_ID: DroidBotOperation
        },
        'main': {
            STATE_ID: [OPERATION_ID]
        },
        'default_policy': EVENT_POLICY_VAL
    }
    import app_event
    valid_event_policies = [app_event.POLICY_NONE, app_event.POLICY_MONKEY, app_event.POLICY_RANDOM,
                            app_event.POLICY_STATIC, app_event.POLICY_DYNAMIC, app_event.POLICY_UTG_DYNAMIC]

    def __init__(self, script_dict):
        self.tag = self.__class__.__name__
        self.logger = logging.getLogger(self.tag)
        self.script_dict = script_dict
        self.views = {}
        self.states = {}
        self.operations = {}
        self.main = {}
        self.default_policy = None
        self.parse()

    def parse(self):
        self.check_grammar_type(self.script_dict, self.script_grammar, self.tag)
        self.parse_default_policy()
        self.parse_views()
        self.parse_states()
        self.parse_operations()
        self.parse_main()
        self.check_duplicated_ids()
        self.check_id_not_defined()

    def parse_views(self):
        script_key = 'views'
        script_value = self.check_and_get_script_value(script_key)
        for view_id in script_value:
            self.check_grammar_identifier_is_valid(view_id)
            view_selector_dict = script_value[view_id]
            view_selector = ViewSelector(view_selector_dict, self)
            self.views[view_id] = view_selector

    def parse_states(self):
        script_key = 'states'
        script_value = self.check_and_get_script_value(script_key)
        for state_id in script_value:
            self.check_grammar_identifier_is_valid(state_id)
            state_selector_dict = script_value[state_id]
            state_seletor = StateSelector(state_selector_dict, self)
            self.states[state_id] = state_seletor

    def parse_operations(self):
        script_key = 'operations'
        script_value = self.check_and_get_script_value(script_key)
        for operation_id in script_value:
            self.check_grammar_identifier_is_valid(operation_id)
            operation_dict = script_value[operation_id]
            operation = DroidBotOperation(operation_dict, self)
            self.operations[operation_id] = operation

    def parse_main(self):
        script_key = 'main'
        script_value = self.check_and_get_script_value(script_key)
        for state_id in script_value:
            self.check_grammar_identifier_is_valid(state_id)
            operation_ids = script_value[state_id]
            for operation_id in operation_ids:
                self.check_grammar_identifier_is_valid(operation_id)
            self.main[state_id] = operation_ids

    def parse_default_policy(self):
        script_key = 'default_policy'
        script_value = self.check_and_get_script_value(script_key)
        self.check_grammar_key_is_valid(script_value, self.valid_event_policies, self.tag)
        self.default_policy = script_value

    @staticmethod
    def check_grammar_type(value, grammar, tag):
        if not isinstance(value, type(grammar)):
            msg = '%s\' type should be %s, %s given' % (tag, type(grammar), type(value))
            raise ScriptSyntaxError(msg)

    @staticmethod
    def check_grammar_key_is_valid(value, valid_keys, tag):
        if not value in valid_keys:
            msg = '%s\'s key should be %s, %s given' % (tag, list(valid_keys), value)
            raise ScriptSyntaxError(msg)

    @staticmethod
    def check_grammar_has_key(dict_keys, required_key, tag):
        if not required_key in dict_keys:
            msg = 'key required in %s: %s' % (tag, required_key)
            raise ScriptSyntaxError(msg)

    @staticmethod
    def check_grammar_identifier_is_valid(value):
        m = IDENTIFIER_RE.match(value)
        if not m:
            msg = "invalid identifier: %s" % value
            raise ScriptSyntaxError(msg)

    @staticmethod
    def check_grammar_is_coordinate(value):
        if not isinstance(value, tuple) or len(value) != 2:
            msg = "illegal coordinate format: %s, should be 2-tuple" % value
            raise ScriptSyntaxError(msg)
        if not isinstance(value[0], int) or not isinstance(value[1], int):
            msg = "illegal coordinate value: %s, should be integer" % value
            raise ScriptSyntaxError(msg)

    def check_and_get_script_value(self, script_key):
        self.check_grammar_has_key(self.script_dict, script_key, self.tag)
        key_tag = "%s.%s" % (self.tag, script_key)
        script_value = self.script_dict[script_key]
        grammar_value = self.script_grammar[script_key]
        self.check_grammar_type(script_value, grammar_value, key_tag)
        return script_value

    def check_duplicated_ids(self):
        all_ids = []
        all_ids.extend(self.views)
        all_ids.extend(self.states)
        all_ids.extend(self.operations)
        all_ids_set = set(all_ids)
        if len(all_ids) > len(all_ids_set):
            msg = "duplicated identifier definition"
            raise ScriptSyntaxError(msg)
        if DEFAULT_ID in all_ids_set:
            msg = "defining reserved identifier: %s" % DEFAULT_ID
            raise ScriptSyntaxError(msg)

    def check_id_not_defined(self):
        defined_view_ids = set()
        defined_view_ids.update(self.views)
        used_view_ids = set()
        for state_id in self.states:
            state_selector = self.states[state_id]
            used_view_ids.update(state_selector.get_used_views())
        for operation_id in self.operations:
            operation = self.operations[operation_id]
            used_view_ids.update(operation.get_used_views())
        if not defined_view_ids.issuperset(used_view_ids):
            undefined_view_ids = used_view_ids - defined_view_ids
            msg = "using undefined views: %s" % list(undefined_view_ids)
            raise ScriptSyntaxError(msg)

        defined_state_ids = set()
        defined_state_ids.update(self.states)
        used_state_ids = set()
        used_state_ids.update(self.main)
        if not defined_state_ids.issuperset(used_state_ids):
            undefined_state_ids = used_state_ids - defined_state_ids
            msg = "using undefined states: %s" % list(undefined_state_ids)
            raise ScriptSyntaxError(msg)

        defined_operation_ids = set()
        defined_operation_ids.update(self.operations)
        used_operation_ids = set()
        for state_id in self.main:
            used_operation_ids.update(self.main[state_id])
        for operation_id in self.operations:
            operation = self.operations[operation_id]
            used_operation_ids.update(operation.get_used_operations())
        if not defined_operation_ids.issuperset(used_operation_ids):
            undefined_operation_ids = used_operation_ids - defined_operation_ids
            msg = "using undefined operations: %s" % list(undefined_operation_ids)
            raise ScriptSyntaxError(msg)


class ViewSelector(object):
    """
    selector used to select a view
    """
    selector_grammar = {
        'text': REGEX_VAL,
        'resource-id': REGEX_VAL,
        'class': REGEX_VAL,
        'package': REGEX_VAL,
        'out-coordinates': [(INTEGER_VAL, INTEGER_VAL)],
        'in-coordinates': [(INTEGER_VAL, INTEGER_VAL)]
    }

    def __init__(self, selector_dict, script):
        self.tag = self.__class__.__name__
        self.selector_dict = selector_dict
        self.text_re = None
        self.resource_id_re = None
        self.class_re = None
        self.package_re = None
        self.script = script
        self.out_coordinates = []
        self.in_coordinates = []
        self.parse()

    def parse(self):
        DroidBotScript.check_grammar_type(self.selector_dict, self.selector_grammar, self.tag)
        for selector_key in self.selector_dict:
            DroidBotScript.check_grammar_key_is_valid(selector_key, self.selector_grammar, self.tag)
            selector_value = self.selector_dict[selector_key]
            grammar_value = self.selector_grammar[selector_key]
            key_tag = "%s.%s" % (self.tag, selector_key)
            DroidBotScript.check_grammar_type(selector_value, grammar_value, key_tag)
            if selector_key is 'text':
                self.text_re = re.compile(selector_value)
            elif selector_key is 'resource_id':
                self.resource_id_re = re.compile(selector_value)
            elif selector_key is 'class':
                self.class_re = re.compile(selector_value)
            elif selector_key is 'package':
                self.package_re = re.compile(selector_value)
            elif selector_key is 'out_coordinates':
                for out_coordinate in grammar_value:
                    DroidBotScript.check_grammar_is_coordinate(out_coordinate)
                    self.out_coordinates.append(out_coordinate)
            elif selector_key is 'in_coordinates':
                for in_coordinate in grammar_value:
                    DroidBotScript.check_grammar_is_coordinate(in_coordinate)
                    self.in_coordinates.append(in_coordinate)

    def match(self, view_dict):
        """
        return True if this view_selector matches a view_dict
        @param view_dict: a view in dict, element of DeviceState.views
        @return:
        """
        if 'text' in view_dict and 'resource-id' in view_dict \
            and 'class' in view_dict and 'package' in view_dict \
            and 'bounds' in view_dict:
            pass
        else:
            return False
        if self.text_re and self.text_re.match(view_dict['text']):
            return False
        if self.resource_id_re and self.resource_id_re.match(view_dict['resource-id']):
            return False
        if self.class_re and self.class_re.match(view_dict['class']):
            return False
        if self.package_re and self.package_re.match(view_dict['package']):
            return False
        bounds = view_dict['bounds']
        bound_x_min = bounds[0][0]
        bound_x_max = bounds[1][0]
        bound_y_min = bounds[0][1]
        bound_y_max = bounds[1][1]
        for (x, y) in self.in_coordinates:
            if x < bound_x_min or x > bound_x_max or y < bound_y_min or y > bound_y_max:
                return False
        for (x, y) in self.out_coordinates:
            if bound_x_min < x < bound_x_max and bound_y_min < y < bound_y_max:
                return False
        return True


class StateSelector(object):
    """
    selector used to select a UI state
    """
    selector_grammar = {
        'activity': REGEX_VAL,
        'services': [REGEX_VAL],
        'views': [ViewSelector]
    }

    def __init__(self, selector_dict, script):
        self.tag = self.__class__.__name__
        self.selector_dict = selector_dict
        self.script = script
        self.activity_re = None
        self.service_re_set = set()
        self.views = set()
        self.parse()

    def get_used_views(self):
        return set(self.views)

    def parse(self):
        DroidBotScript.check_grammar_type(self.selector_dict, self.selector_grammar, self.tag)
        for selector_key in self.selector_dict:
            DroidBotScript.check_grammar_key_is_valid(selector_key, self.selector_grammar, self.tag)
            selector_value = self.selector_dict[selector_key]
            grammar_value = self.selector_grammar[selector_key]
            key_tag = "%s.%s" % (self.tag, selector_key)
            DroidBotScript.check_grammar_type(selector_value, grammar_value, key_tag)
            if selector_key is 'activity':
                self.activity_re = re.compile(selector_value)
            elif selector_key is 'services':
                for service_re_str in selector_value:
                    service_re = re.compile(service_re_str)
                    self.service_re_set.add(service_re)
            elif selector_key is 'views':
                for view_id in selector_value:
                    DroidBotScript.check_grammar_key_is_valid(view_id, self.script.views, key_tag)
                    self.views.add(self.script.views[view_id])

    def match(self, device_state):
        """
        check if the selector matches the DeviceState
        @param device_state: DeviceState
        @return:
        """
        if self.activity_re and self.activity_re.match(device_state.foreground_activity):
            return False
        for service_re in self.service_re_set:
            service_re_matched = False
            if device_state.background_services is None:
                return False
            if not isinstance(device_state.background_services, list):
                return False
            for background_service in device_state.background_services:
                if service_re.match(background_service):
                    service_re_matched = True
                    break
            if not service_re_matched:
                return False
        for view_selector in self.views:
            view_selector_matched = False
            view_dicts = device_state.views
            if view_dicts is None:
                return False
            if not isinstance(view_dicts, list):
                return False
            for view_dict in view_dicts:
                if view_selector.match(view_dict):
                    view_selector_matched = True
                    break
            if not view_selector_matched:
                return False
        return True


class DroidBotOperation(object):
    """
    an operation is what DroidBot do to target device
    It might be a set of events, or an event policy
    """
    custom_operation_grammar = {
        'operation_type': 'custom',
        'events': [ScriptEvent]
    }
    possible_operation_types = ['custom']

    def __init__(self, operation_dict, script):
        self.tag = self.__class__.__name__
        self.operation_dict = operation_dict
        self.operation_type = None
        self.script = script
        self.events = []
        self.used_views = set()
        self.parse()

    def parse(self):
        operation_dict = self.operation_dict
        DroidBotScript.check_grammar_has_key(operation_dict, 'operation_type', self.tag)
        operation_type = self.operation_dict['operation_type']
        if operation_type not in self.possible_operation_types:
            msg = "invalid operation type: %s" % operation_type
            raise ScriptSyntaxError(msg)
        self.operation_type = operation_type
        self.tag = "%s (%s)" % (self.tag, operation_type)
        if operation_type is 'custom':
            operation_grammar = self.custom_operation_grammar
            DroidBotScript.check_grammar_has_key(self.operation_dict, 'events', self.tag)
            for operation_key in operation_dict:
                DroidBotScript.check_grammar_key_is_valid(operation_key, operation_grammar, self.tag)
            for event_dict in operation_dict['events']:
                script_event = ScriptEvent(event_dict)
                self.events.append(script_event)
                if 'target_view' in event_dict:
                    self.used_views.add(event_dict['target_view'])

    def get_used_views(self):
        return self.used_views

    def get_used_operations(self):
        if 'operations' in self.operation_dict:
            return set(self.operation_dict['operations'])
        return None


class ScriptEvent(AppEvent):
    """
    an event define in DroidBotScript
    """
    # the grammar of ScriptEvent is similar with the AppEvent in dict format
    event_grammar = {
    }

    def __init__(self, event_dict):
        self.event_dict = event_dict

    @staticmethod
    def get_random_instance(device, app):
        pass

    def send(self, device):
        pass


class ScriptException(DroidBotException):
    """
    Exception during parsing DroidScript
    """
    pass


class ScriptSyntaxError(ScriptException):
    """
    syntax error of DroidBotScript
    """
    pass
