import unittest

from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        x = {'source': 'x-invalid'}
        resp = await self.api.tag(query_string=x)
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        resp = await self.api.tag()
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['totalTags'], len(x['tags']))


if __name__ == '__main__':
    unittest.main()
