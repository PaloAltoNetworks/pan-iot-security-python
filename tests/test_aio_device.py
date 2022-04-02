from datetime import datetime, timedelta, timezone
import unittest

import paniot
from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        resp = await self.api.device(pagelength=0)
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        with self.assertRaises(paniot.ArgsError) as e:
            resp = await self.api.device_details()
        self.assertEqual(str(e.exception),
                         'deviceid or ip required')

    async def test_03(self):
        with self.assertRaises(paniot.ArgsError) as e:
            resp = await self.api.device_details(
                ip='x',
                deviceid='x')
        self.assertEqual(str(e.exception),
                         'deviceid and ip cannot be used at the same time')

    async def test_04(self):
        resp = await self.api.device_details(ip='x')
        self.assertEqual(resp.status, 404)

    async def test_05(self):
        resp = await self.api.device_details(deviceid='x')
        self.assertEqual(resp.status, 404)

    async def test_06(self):
        resp = await self.api.device(pagelength=1)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['total'], 1)
        self.assertEqual(len(x['devices']), 1)

        deviceid = x['devices'][0]['deviceid']
        ip = x['devices'][0]['ip_address']
        resp = await self.api.device_details(deviceid=deviceid)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['deviceid'], deviceid)

        resp = await self.api.device_details(ip=ip)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['devices'][0]['ip_address'], ip)

    async def test_07(self):
        resp = await self.api.device(detail=True)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        self.assertEqual(x['total'], len(x['devices']))

    async def test_08(self):
        d = datetime.now(tz=timezone.utc) + timedelta(seconds=10)
        stime = d.strftime('%Y-%m-%dT%H:%M:%SZ')
        resp = await self.api.device(stime=stime)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        t = await resp.text()
        msg = 'devices in future stime %s: ' % stime
        msg += t
        self.assertEqual(x['total'], 0, msg)
        self.assertEqual(len(x['devices']), 0, msg)

    async def test_09(self):
        total = 0
        async for x in self.api.devices_all():
            total += 1
            if total > 1050:
                break
