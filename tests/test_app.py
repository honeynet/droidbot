import unittest

from droidbot.app import App


class FakeApk:
    def __init__(self, main_activities, fallback):
        self.main_activities = set(main_activities)
        self.fallback = fallback

    def get_main_activities(self):
        return self.main_activities

    def get_main_activity(self):
        return self.fallback


class AppMainActivityTest(unittest.TestCase):
    def test_prefers_launcher_owned_by_target_package(self):
        app = App.__new__(App)
        app.package_name = "org.wikipedia"
        app.apk = FakeApk(
            {
                "leakcanary.internal.activity.LeakLauncherActivity",
                "org.wikipedia.DefaultIcon",
            },
            "leakcanary.internal.activity.LeakLauncherActivity",
        )

        self.assertEqual("org.wikipedia.DefaultIcon", app._get_main_activity())

    def test_uses_androguard_fallback_without_package_launcher(self):
        app = App.__new__(App)
        app.package_name = "org.wikipedia"
        app.apk = FakeApk(
            {"external.launcher.Activity"},
            "external.launcher.Activity",
        )

        self.assertEqual("external.launcher.Activity", app._get_main_activity())


if __name__ == "__main__":
    unittest.main()
