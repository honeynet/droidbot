# DroidBotScript
# This file contains the definition of DroidBotScript
# DroidBotScript is a domain-specific language, which defines how DroidBot interacts with target app
import re
from app_event import AppEvent


class DroidBotScript(object):
    """
    DroidBotScript is a DSL which defines how DroidBot interacts with target app
    """
    script_syntax = {
        'views': {
            '<view_id>': ViewSelector
        },
        'states': {
            '<state_id>': StateSeletor
        },
        'operations': {
            '<operation_id>': DroidBotOperation
        },
        'main': {
            '<state_id>': '<operation_id>'
        }
    }

    def __init__(self, script_json):
        pass


class ViewSelector(object):
    """
    selector used to select a view
    """
    selector_syntax = {
        'view_id': '<regex>',
        'content': '<regex>',
        'class': '<regex>'
    }
    def __init__(self, selector_json):
        pass


class StateSeletor(object):
    """
    selector used to select a UI state
    """
    selector_syntax = {
        'activity': '<regex>',
        'service': '<regex>',
        'views': ['<view_id>']
    }
    def __init__(self, selector_json):
        pass


class DroidBotOperation(object):
    """
    an operation is what DroidBot do to target device
    It might be a set of events, or an event policy
    """
    custom_operation_syntax = {
        'operation_type': 'custom',
        'events': [AppEvent],
        'event_duration': '<int>',
        'event_interval': '<int>',
        'event_count': '<int>'
    }
    policy_operation_syntax = {
        'operation_type': 'policy',
        'event_policy': '<event_policy>',
        'event_duration': '<int>',
        'event_interval': '<int>',
        'event_count': '<int>'
    }
    hybrid_operation_syntax = {
        'operation_type': 'hybrid',
        'operations': ['<operation_id>'],
        'hybrid_policy': 'random|loop'
    }
    def __init__(self):
        pass

