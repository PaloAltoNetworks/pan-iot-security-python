import unittest

from . import mixin


# XXX offset, pagelength

class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        x = {'profile': 'x-invalid'}
        resp = self.api.policy(query_string=x)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(x['total'], 0)
        self.assertEqual(len(x['policies']), 0)

    def test_02(self):
        resp = self.api.policy()
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertGreaterEqual(x['total'], 0)
        self.assertEqual(len(x['policies']), x['total'])

        if len(x['policies']) > 0:
            query_string = {
                'profile': x['policies'][0]['sourceProfiles'][0],
            }
            resp = self.api.policy(query_string=query_string)
            self.assertEqual(resp.status_code, 200)
            x = resp.json()
            total = x['total']
            self.assertGreaterEqual(total, 1)
            self.assertEqual(len(x['policies']), total)

            query_string['profile'] += ',x-invalid'
            resp = self.api.policy(query_string=query_string)
            self.assertEqual(resp.status_code, 200)
            x = resp.json()
            self.assertEqual(x['total'], total)
            self.assertEqual(len(x['policies']), total)
