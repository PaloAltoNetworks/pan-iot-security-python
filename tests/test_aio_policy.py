import unittest

from . import mixin


# XXX offset, pagelength

class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        x = {'profile': 'x-invalid'}
        resp = await self.api.policy(query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['total'], 0)
        self.assertEqual(len(x['policies']), 0)

    async def test_02(self):
        resp = await self.api.policy()
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertGreaterEqual(x['total'], 0)
        self.assertEqual(len(x['policies']), x['total'])

        if len(x['policies']) > 0:
            query_string = {
                'profile': x['policies'][0]['sourceProfiles'][0],
            }
            resp = await self.api.policy(query_string=query_string)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            total = x['total']
            self.assertGreaterEqual(total, 1)
            self.assertEqual(len(x['policies']), total)

            query_string['profile'] += ',x-invalid'
            resp = await self.api.policy(query_string=query_string)
            self.assertEqual(resp.status, 200)
            x = await resp.json()
            self.assertEqual(x['total'], total)
            self.assertEqual(len(x['policies']), total)
