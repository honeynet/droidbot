# This file is responsible for generating events to interact with app at runtime
# The events includes:
#     1. UI events. click, touch, etc
#     2, intent events. broadcast events of App installed, new SMS, etc.
# The intention of these events is to exploit more mal-behaviours of app as soon as possible
__author__ = 'liyc'

event_policies = [
    "none",
    "monkey",
    "static",
    "dynamic",
    "file"
]

class AppEvent(object):
    """
    The base class of all events
    """
    # TODO implement this class and its subclasses
    pass

class UIEvent(AppEvent):
    """
    This class describes a UI event of app, such as touch, click, etc
    """
    pass

class ExtendedUIEvent(UIEvent):
    """
    An extended UI event, which knows the UI state on which it is performing
    """
    pass

class IntentEvent(AppEvent):
    """
    An event describing an intent
    """
    pass

class AppEventManager(object):
    """
    This class manages all events to send during app running
    """

    def __init__(self, package_name):
        """
        construct a new AppEventManager instance
        :param package_name: tha package name of app
        :return:
        """
        self.package_name = package_name
        self.event_factory = None
        self.events = []

    def add_event(self, event):
        """
        add one event to the event list
        :param event: the event to be added, should be subclass of AppEvent
        :return:
        """
        self.events.append(event)

    def dump(self, file):
        """
        dump the event information to a file
        :param file: the file path to output the events
        :return:
        """
        # TODO implement this method

    def send_event(self, event, state=None):
        """
        send one event to device based on current app state
        :param event: the event to be sent
        :return:
        """
        # TODO implement this method

    def on_state_update(self, old_state, new_state):
        """
        callback method invoked by AppstateMonitor
        :param old_state: origin state of App
        :param new_state: new state of App
        :return:
        """
        # TODO implement this method

    def set_event_factory(self, event_factory):
        """
        set event factory of the app
        :param event_factory: the factory used to generate events
        :return:
        """
        self.event_factory = event_factory


class EventFactory(object):
    """
    This class is responsible for generating events to stimulate more app behaviour
    It should call AppEventManager.send_event method continuously
    """
    # TODO implement this class and its subclasses
    pass


class DummyEventFactory(EventFactory):
    """
    A dummy factory which produces AppEventManager.send_event method in a random manner
    """
    pass


class StaticEventFactory(EventFactory):
    """
    A factory which produces events based on static analysis result
    for example, manifest file and sensitive API it used
    """
    pass


class DynamicEventFactory(EventFactory):
    """
    A much wiser factory which produces events based on the current app state
    """
    pass


class FileEventFactory(EventFactory):
    """
    factory which produces events from file
    """
    pass