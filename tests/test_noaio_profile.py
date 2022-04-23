import unittest

from . import mixin

MINIMUM = 3000


class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.profile()
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertGreaterEqual(x['count'], MINIMUM)
        self.assertEqual(len(x['mapping']), x['count'])
