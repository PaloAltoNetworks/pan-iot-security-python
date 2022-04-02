import unittest

from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.device_update()
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        json = '{"tag":"test-tag"}'
        resp = await self.api.device_update(json=json)
        self.assertEqual(resp.status, 400)
        x = await resp.json()
        msg = await resp.text()
        try:
            self.assertEqual(
                x['validations']['body'][0]['property'],
                'instance.deviceidlist', msg)
        except KeyError as e:
            self.fail('KeyError %s: %s' % (e, msg))
