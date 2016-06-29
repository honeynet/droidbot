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
            STATE_ID: OPERATION_ID
        }
    }

    def __init__(self, script_dict):
        self.tag = self.__class__.__name__
        self.logger = logging.getLogger(self.tag)
        self.script_dict = script_dict
        self.views = {}
        self.states = {}
        self.operations = {}
        self.main = {}
        self.parse()

    def parse(self):
        script_dict = self.script_dict
        grammar = DroidBotScript.script_grammar
        self.check_grammar_type(script_dict, grammar, self.tag)
        for script_key in script_dict:
            self.check_grammar_key_is_valid(script_key, grammar, self.tag)
            key_tag = "%s.%s" % (self.tag, script_key)
            script_value = script_dict[script_key]
            grammar_value = grammar[script_key]
            self.check_grammar_type(script_value, grammar_value, key_tag)
            if script_key is 'views':
                for view_id in script_value:
                    self.check_grammar_identifier_is_valid(view_id)
                    view_selector_dict = script_value[view_id]
                    view_selector = ViewSelector(view_selector_dict)
                    self.views[view_id] = view_selector
            elif script_key is 'states':
                for state_id in script_value:
                    self.check_grammar_identifier_is_valid(state_id)
                    state_selector_dict = script_value[state_id]
                    state_seletor = StateSelector(state_selector_dict)
                    self.states[state_id] = state_seletor
            elif script_key is 'operations':
                for operation_id in script_value:
                    self.check_grammar_identifier_is_valid(operation_id)
                    operation_dict = script_value[operation_id]
                    operation = DroidBotOperation(operation_dict)
                    self.states[operation_id] = operation
            elif script_key is 'main':
                for state_id in script_value:
                    self.check_grammar_identifier_is_valid(state_id)
                    operation_id = script_value[state_id]
                    self.check_grammar_identifier_is_valid(operation_id)
                    self.operations[state_id] = operation_id
        self.check_duplicated_ids()
        self.check_id_not_defined()

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
        defined_view_ids.add(DEFAULT_ID)
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
        defined_state_ids.add(DEFAULT_ID)
        used_state_ids = set()
        used_state_ids.update(self.main)
        if not defined_state_ids.issuperset(used_state_ids):
            undefined_state_ids = used_state_ids - defined_state_ids
            msg = "using undefined states: %s" % list(undefined_state_ids)
            raise ScriptSyntaxError(msg)

        defined_operation_ids = set()
        defined_operation_ids.update(self.operations)
        defined_operation_ids.add(DEFAULT_ID)
        used_operation_ids = set()
        used_operation_ids.update(self.main.values())
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
        'resource_id': REGEX_VAL,
        'class': REGEX_VAL,
        'package': REGEX_VAL,
        'out_coordinates': [(INTEGER_VAL, INTEGER_VAL)],
        'in_coordinates': [(INTEGER_VAL, INTEGER_VAL)]
    }

    def __init__(self, selector_dict):
        self.tag = self.__class__.__name__
        self.selector_dict = selector_dict
        self.text_re = None
        self.resource_id_re = None
        self.class_re = None
        self.package_re = None
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


class StateSelector(object):
    """
    selector used to select a UI state
    """
    selector_grammar = {
        'activity': REGEX_VAL,
        'services': [REGEX_VAL],
        'views': [VIEW_ID]
    }

    def __init__(self, selector_dict):
        self.tag = self.__class__.__name__
        self.selector_dict = selector_dict
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
                    self.views.add(view_id)


class DroidBotOperation(object):
    """
    an operation is what DroidBot do to target device
    It might be a set of events, or an event policy
    """
    custom_operation_grammar = {
        'operation_type': 'custom',
        'events': [AppEvent],
        'event_duration': INTEGER_VAL,
        'event_interval': INTEGER_VAL,
        'event_count': INTEGER_VAL
    }
    policy_operation_grammar = {
        'operation_type': 'policy',
        'event_policy': EVENT_POLICY_VAL,
        'event_duration': INTEGER_VAL,
        'event_interval': INTEGER_VAL,
        'event_count': INTEGER_VAL
    }
    hybrid_operation_grammar = {
        'operation_type': 'hybrid',
        'operations': [OPERATION_ID],
    }

    def __init__(self, operation_dict):
        self.tag = self.__class__.__name__
        self.operation_dict = operation_dict
        self.used_views = set()
        self.parse()

    def parse(self):
        pass

    def get_used_views(self):
        return self.used_views


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
