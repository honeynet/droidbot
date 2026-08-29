import argparse
import unittest

from droidbot.input_policy import (
    NavigationStagnationTracker,
    POLICY_GREEDY_DFS,
    UtgGreedySearchPolicy,
)
from droidbot.start import positive_int


class FakeDevice(object):
    humanoid = None


class FakeApp(object):
    pass


class FakeState(object):
    def __init__(self, state_str):
        self.state_str = state_str

    def get_app_activity_depth(self, app):
        return 0

    def get_possible_input(self):
        return []


class FakeEvent(object):
    def __init__(self, event_str):
        self.event_str = event_str

    def get_event_str(self, state):
        return self.event_str


class FakeUtg(object):
    def __init__(self, targets, routes):
        self.targets = targets
        self.routes = routes

    def is_event_explored(self, event, state):
        return True

    def get_reachable_states(self, current_state):
        return self.targets

    def is_state_explored(self, state):
        return False

    def get_navigation_steps(self, from_state, to_state):
        event, step_count = self.routes[to_state.state_str]
        return [(None, event)] * step_count


class NavigationStagnationTrackerTest(unittest.TestCase):
    def test_marks_signature_stale_after_configured_attempts(self):
        tracker = NavigationStagnationTracker(limit=8)
        signature = ("state-a", "target", "touch-button", 4)

        for _ in range(8):
            self.assertFalse(tracker.is_stale(signature))

        self.assertTrue(tracker.is_stale(signature))

    def test_counts_interleaved_signatures_independently(self):
        tracker = NavigationStagnationTracker(limit=2)
        signature_a = ("state-a", "target", "touch-button", 4)
        signature_b = ("state-b", "target", "BACK", 4)

        self.assertFalse(tracker.is_stale(signature_a))
        self.assertFalse(tracker.is_stale(signature_b))
        self.assertFalse(tracker.is_stale(signature_a))
        self.assertFalse(tracker.is_stale(signature_b))
        self.assertTrue(tracker.is_stale(signature_a))
        self.assertTrue(tracker.is_stale(signature_b))

    def test_reset_forgets_attempts_after_progress(self):
        tracker = NavigationStagnationTracker(limit=1)
        signature = ("state-a", "target", "touch-button", 4)

        self.assertFalse(tracker.is_stale(signature))
        tracker.reset()

        self.assertFalse(tracker.is_stale(signature))

    def test_rejects_non_positive_limit(self):
        with self.assertRaisesRegex(ValueError, "must be positive"):
            NavigationStagnationTracker(limit=0)

    def test_cli_limit_must_be_positive(self):
        self.assertEqual(positive_int("8"), 8)
        with self.assertRaisesRegex(
            argparse.ArgumentTypeError, "must be a positive integer"
        ):
            positive_int("0")

    def test_policy_chooses_another_target_after_stagnation(self):
        current_state = FakeState("current")
        stale_target = FakeState("stale-target")
        alternate_target = FakeState("alternate-target")
        stale_event = FakeEvent("touch-button")
        alternate_event = FakeEvent("touch-link")
        policy = UtgGreedySearchPolicy(
            FakeDevice(),
            FakeApp(),
            random_input=False,
            search_method=POLICY_GREEDY_DFS,
            navigation_stagnation_limit=2,
        )
        policy.utg = FakeUtg(
            [stale_target, alternate_target],
            {
                stale_target.state_str: (stale_event, 4),
                alternate_target.state_str: (alternate_event, 3),
            },
        )
        policy.current_state = current_state

        self.assertIs(policy.generate_event_based_on_utg(), stale_event)
        self.assertIs(policy.generate_event_based_on_utg(), stale_event)
        self.assertIs(policy.generate_event_based_on_utg(), alternate_event)

    def test_policy_resets_attempts_when_route_gets_shorter(self):
        current_state = FakeState("current")
        target = FakeState("target")
        event = FakeEvent("touch-button")
        policy = UtgGreedySearchPolicy(
            FakeDevice(),
            FakeApp(),
            random_input=False,
            search_method=POLICY_GREEDY_DFS,
            navigation_stagnation_limit=2,
        )
        fake_utg = FakeUtg([target], {target.state_str: (event, 4)})
        policy.utg = fake_utg
        policy.current_state = current_state

        self.assertIs(policy.generate_event_based_on_utg(), event)
        self.assertIs(policy.generate_event_based_on_utg(), event)
        fake_utg.routes[target.state_str] = (event, 3)

        self.assertIs(policy.generate_event_based_on_utg(), event)


if __name__ == "__main__":
    unittest.main()
