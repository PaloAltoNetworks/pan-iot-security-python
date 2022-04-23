import unittest

from . import mixin

MINIMUM = 3000


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.profile()
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertGreaterEqual(x['count'], MINIMUM)
        self.assertEqual(len(x['mapping']), x['count'])
