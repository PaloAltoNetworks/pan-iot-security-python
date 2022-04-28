import unittest

from . import mixin


class IotApiTest(mixin.AioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_01(self):
        x = {
            'sortfield': 'x-invalid',
        }
        resp = await self.api.device(query_string=x)
        self.assertEqual(resp.status, 400)

    async def test_02(self):
        key = 'MAC'
        x = {
            'sortfield': key,
            # default: desc
        }
        resp = await self.api.device(detail=True, query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = 'ff:ff:ff:ff:ff:ff'
        for device in x['devices']:
            current = device[key]
            if last < current:
                self.fail('sort desc %s: %s < %s' % (key, last, current))
            last = current

    async def test_03(self):
        key = 'MAC'
        x = {
            'sortfield': key,
            'sortdirection': 'desc',
        }
        resp = await self.api.device(detail=True, query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = 'ff:ff:ff:ff:ff:ff'
        for device in x['devices']:
            current = device[key]
            if last < current:
                self.fail('sort desc %s: %s < %s' % (key, last, current))
            last = current

    async def test_04(self):
        key = 'MAC'
        x = {
            'sortfield': key,
            'sortdirection': 'asc',
        }
        resp = await self.api.device(detail=True, query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = '00:00:00:00:00:00'
        for device in x['devices']:
            # XXX when MAC is nil, key not in response
            # all nil MAC fields will be first for ascending
            if key in device:
                current = device[key]
                if last > current:
                    self.fail('sort asc %s: %s > %s' % (key, last, current))
                last = current

    async def test_05(self):
        x = {
            'sortfield': 'x-invalid',
        }
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 400)

    async def test_06(self):
        key = 'date'
        x = {
            'sortfield': key,
            # default: desc
        }
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = '9999'
        for item in x['items']:
            current = item[key]
            if last < current:
                self.fail('sort desc %s: %s < %s' % (key, last, current))
            last = current

    async def test_07(self):
        key = 'date'
        x = {
            'sortfield': key,
            'sortdirection': 'desc',
        }
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = '9999'
        for item in x['items']:
            current = item[key]
            if last < current:
                self.fail('sort desc %s: %s < %s' % (key, last, current))
            last = current

    async def test_08(self):
        key = 'date'
        x = {
            'sortfield': key,
            'sortdirection': 'asc',
        }
        resp = await self.api.alert(query_string=x)
        self.assertEqual(resp.status, 200)
        x = await resp.json()
        last = '0000'
        for item in x['items']:
            current = item[key]
            if last > current:
                self.fail('sort asc %s: %s > %s' % (key, last, current))
            last = current
