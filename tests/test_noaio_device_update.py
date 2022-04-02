import unittest

from . import mixin


class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.device_update()
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        json = '{"tag":"test-tag"}'
        resp = self.api.device_update(json=json)
        self.assertEqual(resp.status_code, 400)
        x = resp.json()
        msg = resp.text
        try:
            self.assertEqual(
                x['validations']['body'][0]['property'],
                'instance.deviceidlist', msg)
        except KeyError as e:
            self.fail('KeyError %s: %s' % (e, msg))
