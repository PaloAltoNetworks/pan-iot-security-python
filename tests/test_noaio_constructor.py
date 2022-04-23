import asyncio
import unittest

import paniot


class IotApiTest(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, 'api') and hasattr(self.api, 'session'):
            self.api.session.close()

    def test_00(self):
        self.assertRaises(RuntimeError, asyncio.get_running_loop)

    def test_01(self):
        kwargs = {}
        with self.assertRaises(paniot.ArgsError) as e:
            self.api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'customerid required')

    def test_02(self):
        kwargs = {
            'customerid': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            self.api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'access_key_id required')

    def test_03(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            self.api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'access_key required')

    def test_04(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
            'api_version': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            self.api = paniot.IotApi(**kwargs)
        self.assertRegex(str(e.exception),
                         '^Invalid api_version')

    def test_05(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
        }
        self.api = paniot.IotApi(**kwargs)
        with self.assertRaises(paniot.ArgsError) as e:
            self.api.decode_jwt()
        self.assertEqual(str(e.exception),
                         'token is not a JSON Web Signature')

    def test_06(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
        }
        self.api = paniot.IotApi(**kwargs)
        for x in [self.api.device,
                  self.api.device_details,
                  self.api.vulnerability,
                  self.api.alert,
                  self.api.tag,
                  self.api.profile,
                  self.api.policy,
                  self.api.device_update,
                  self.api.vuln_update,
                  self.api.alert_update]:
            self.assertTrue(x.window > 0)
            self.assertTrue(x.rate_limit > 0)
