# This file is responsible for generating events to interact with app at runtime
# The events includes:
#     1. UI events. click, touch, etc
#     2, intent events. broadcast events of App installed, new SMS, etc.
# The intention of these events is to exploit more mal-behaviours of app as soon as possible
__author__ = 'liyc'

class AppEvent(object):
    """
    The base class of all events
    """
    # TODO implement this method and its subclasses
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

    def send_event(self, event):
        """
        send one event to device
        in most case, this method should be a callback by AppStateMonitor
        :param event: the event to be sent
        :return:
        """
        # TODO implement this method