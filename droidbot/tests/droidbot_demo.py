__author__ = 'yuanchun'

from droidbot.app_event import StateBasedEventFactory, AppEventManager, AppEvent
from types.device import Device, App


class MyEventFactory(StateBasedEventFactory):
    def gen_event_based_on_state(self, state):
        print state
        return AppEvent.get_random_instance(self.device, self.app)


if __name__ == "__main__":
    d = Device()
    a = App(app_path="/home/liyc/experiments/apks/hot_apks_types/Personalization/net.zedge.android.apk")
    event_manager = AppEventManager(device=d, app=a, event_policy="none", event_count=100, event_interval=3,
                                    event_duration=100)
    event_manager.set_event_factory(MyEventFactory(d, a))
    d.install_app(a)
    event_manager.start()
    d.uninstall_app(a)
