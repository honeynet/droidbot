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
    script_syntax = {
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
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def check_syntax(script):
        syntax = DroidBotScript.script_syntax
        if not isinstance(script, type(syntax)):
            print 'DroidBotScript should be %s, %s given' % (type(syntax), type(script))
        for script_key in script:
            if script_key not in syntax:
                print 'unknown script_key: %s' % script_key
            script_value = script[script_key]
            script_value_syntax = syntax[script_key]
            # TODO continue implementing this


class ViewSelector(object):
    """
    selector used to select a view
    """
    selector_syntax = {
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
    selector_syntax = {
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
    custom_operation_syntax = {
        'operation_type': 'custom',
        'events': [AppEvent],
        'event_duration': INTEGER_VAL,
        'event_interval': INTEGER_VAL,
        'event_count': INTEGER_VAL
    }
    policy_operation_syntax = {
        'operation_type': 'policy',
        'event_policy': EVENT_POLICY_VAL,
        'event_duration': INTEGER_VAL,
        'event_interval': INTEGER_VAL,
        'event_count': INTEGER_VAL
    }
    hybrid_operation_syntax = {
        'operation_type': 'hybrid',
        'operations': [OPERATION_ID],
    }
    def __init__(self):
        pass

