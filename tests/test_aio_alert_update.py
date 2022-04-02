import json
import unittest

from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.alert_update()
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        id = 'X' * 12
        resp = await self.api.alert_update(id=id)
        self.assertEqual(resp.status, 400)

    async def test_03(self):
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
            resp = await self.api.alert_update(id=id, json=x)
            self.assertEqual(resp.status, 404, x)
