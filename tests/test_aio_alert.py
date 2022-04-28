from datetime import datetime, timedelta, timezone
import unittest

from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.alert(pagelength=0)
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        x = {'type': 'x-invalid'}
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 400)

        x['type'] = 'policy_alert'
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 200)
        await resp.json()

    async def test_03(self):
        x = {'resolved': 'x-invalid'}
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 400)

    async def test_04(self):
        resp = await self.api.alert(pagelength=1)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertIn(len(x['items']), (0, 1))

        total = x['total']
        resp = await self.api.alert(offset=total)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(len(x['items']), 0)

        total_resolved = 0
        async for ok, x in self.api.alerts_all(
                query_string={'resolved': 'yes'}):
            self.assertTrue(ok)
            total_resolved += 1
        total_unresolved = 0
        async for ok, x in self.api.alerts_all(
                query_string={'resolved': 'no'}):
            self.assertTrue(ok)
            total_unresolved += 1
        self.assertEqual(total, total_resolved+total_unresolved,
                         'alert total != resolved+unresolved')

    async def test_05(self):
        d = datetime.now(tz=timezone.utc) + timedelta(seconds=10)
        stime = d.strftime('%Y-%m-%dT%H:%M:%SZ')
        resp = await self.api.alert(stime=stime)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        t = await resp.text()
        msg = 'alerts in future stime %s: ' % stime
        msg += t
        self.assertEqual(x['total'], 0, msg)
        self.assertEqual(len(x['items']), 0, msg)
