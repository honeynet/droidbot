__author__ = 'liyc'

import unittest
from droidbot.types import Intent

class IntentTest(unittest.TestCase):
    """
    test Intent class
    """
    def test_intent_init(self):
        intent = Intent(action='android.intent.action.INSERT',
                        mime_type='vnd.android.cursor.dir/contact',
                        extra_string={
                            'name' : 'Anonymous',
                            'phone' : '123456789'
                        })
        print intent.get_cmd()
        correct = " -a android.intent.action.INSERT" \
                  " -t vnd.android.cursor.dir/contact" \
                  " -e 'phone' '123456789' -e 'name' 'Anonymous'"
        self.assertEqual(intent.get_cmd(), correct)