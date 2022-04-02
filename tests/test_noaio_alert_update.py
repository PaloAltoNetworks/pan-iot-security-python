import json
import unittest

from . import mixin


class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.alert_update()
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        id = 'X' * 12
        resp = self.api.alert_update(id=id)
        self.assertEqual(resp.status_code, 400)

    def test_03(self):
        body = {
            'reason': 'false positive',
            'reason_type': ["No Action Needed"],
            'resolved': 'yes',
        }
        json_body = json.dumps(body)
        tests = [
            body,
            json_body,
            bytes(json_body, 'utf-8'),
            bytearray(json_body, 'utf-8'),
        ]
        id = 'X' * 12
        for x in tests:
            resp = self.api.alert_update(id=id, json=x)
            self.assertEqual(resp.status_code, 404, x)
