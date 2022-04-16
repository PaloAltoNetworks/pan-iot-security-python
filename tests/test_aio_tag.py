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
        if x['totalTags'] <= 1000:
            self.assertEqual(x['totalTags'], len(x['tags']))
        if x['totalTags'] > 0:
            resp = await self.api.tag(pagelength=1)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(len(x['tags']), 1)
            if x['totalTags'] > 1:
                tag0 = x['tags'][0]
                resp = await self.api.tag(offset=0,
                                          pagelength=2)
                self.assertEqual(resp.status, 200)
                x = await resp.json()
                self.assertEqual(len(x['tags']), 2)
                self.assertEqual(x['tags'][0], tag0)
                tag1 = x['tags'][1]
                resp = await self.api.tag(offset=1,
                                          pagelength=1)
                self.assertEqual(resp.status, 200)
                x = await resp.json()
                self.assertEqual(len(x['tags']), 1)
                self.assertEqual(x['tags'][0], tag1)
