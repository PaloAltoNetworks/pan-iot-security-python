import unittest

from . import mixin


class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        x = {'source': 'x-invalid'}
        resp = self.api.tag(query_string=x)
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        resp = self.api.tag()
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['totalTags'], len(x['tags']))
