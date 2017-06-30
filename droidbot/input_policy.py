from input_event import KeyEvent, IntentEvent

POLICY_NONE = "none"
POLICY_MONKEY = "monkey"
POLICY_BFS = "bfs"
POLICY_DFS = "dfs"
POLICY_MANUAL = "manual"
DEFAULT_POLICY = POLICY_DFS

START_RETRY_THRESHOLD = 20


class InputPolicy(object):
    """
    This class is responsible for generating events to stimulate more app behaviour
    It should call AppEventManager.send_event method continuously
    """

    def __init__(self, device, app):
        self.device = device
        self.app = app

    def start(self, event_manager):
        """
        start producing events
        :param event_manager: instance of InputManager
        """
        count = 0
        while event_manager.enabled and count < event_manager.event_count:
            try:
                # make sure the first event is go to HOME screen
                # the second event is to start the app
                if count == 0:
                    event = KeyEvent(name="HOME")
                elif count == 1:
                    event = IntentEvent(self.app.get_start_intent())
                else:
                    event = self.generate_event()
                event_manager.add_event(event)
            except KeyboardInterrupt:
                break
            except StopSendingEventException as e:
                self.device.logger.warning("EventFactory stop sending event: %s" % e)
                break
            # except RuntimeError as e:
            #     self.device.logger.warning(e.message)
            #     break
            except Exception as e:
                self.device.logger.warning("exception in EventFactory: %s" % e)
                import traceback
                traceback.print_exc()
                continue
            count += 1

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
        pass

    def dump(self):
        """
        dump something to file
        @return:
        """
        pass


class NoneInputPolicy(InputPolicy):
    """
    do not send any event
    """

    def __init__(self, device, app):
        super(NoneInputPolicy, self).__init__(device, app)

    def generate_event(self, state=None):
        """
        generate an event
        @param state: DeviceState
        @return:
        """
        return None


class StopSendingEventException(Exception):
    def __init__(self, message):
        self.message = message
