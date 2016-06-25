# DroidBotScript
# This file contains the definition of DroidBotScript
# DroidBotScript is a domain-specific language, which defines how DroidBot interacts with target app
import re
import logging
from app_event import AppEvent

VIEW_ID = '<view_id>'
STATE_ID = '<state_id>'
OPERATION_ID = '<operation_id>'
INTEGER_VAL = '<int>'
REGEX_VAL = '<regex>'
EVENT_POLICY_VAL = '<event_policy>'


class DroidBotScript(object):
    """
    DroidBotScript is a DSL which defines how DroidBot interacts with target app
    """
    script_grammar = {
        'views': {
            VIEW_ID: ViewSelector
        },
        'states': {
            STATE_ID: StateSeletor
        },
        'operations': {
            OPERATION_ID: DroidBotOperation
        },
        'main': {
            STATE_ID: OPERATION_ID
        }
    }

    def __init__(self, script):
        self.tag = self.__class__.__name__
        self.logger = logging.getLogger(self.tag)
        self.script = script

    def parse(self):
        script = self.script
        grammar = DroidBotScript.script_grammar
        if not self.check_grammar_type(script, grammar, self.tag):
            return False
        for script_key in script:
            self.check_grammar_key_is_valid(script_key, grammar, self.tag)
            script_value = script[script_key]
            script_value_grammar = grammar[script_key]

    @staticmethod
    def check_grammar_type(value, grammar, tag):
        if not isinstance(value, type(grammar)):
            print '[syntax error] %s\' type should be %s, %s given' % (tag, type(grammar), type(value))
            return False
        return True

    @staticmethod
    def check_grammar_key_is_valid(value, valid_keys, tag):
        if not value in valid_keys:
            print '[syntax error] %s\'s key should be %s, %s given' % (tag, list(valid_keys), value)
            return False
        return True

    @staticmethod
    def check_grammar_identifier_is_valid(value):
        pass


class ViewSelector(object):
    """
    selector used to select a view
    """
    selector_grammar = {
        'text': REGEX_VAL,
        'resource_id': REGEX_VAL,
        'class': REGEX_VAL,
        'package': REGEX_VAL
    }
    def __init__(self, selector):
        pass


class StateSeletor(object):
    """
    selector used to select a UI state
    """
    selector_grammar = {
        'activity': REGEX_VAL,
        'service': REGEX_VAL,
        'views': [VIEW_ID]
    }
    def __init__(self, selector):
        pass


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
    def __init__(self):
        pass

