import unittest


class WinrmTestCase(unittest.TestCase):

    def assertRaisesWithMessage(self, msg, func, *args, **kwargs):
        try:
          func(*args, **kwargs)
          self.assertFail()
        except Exception as inst:
          self.assertRegexpMatches(inst.message, msg)