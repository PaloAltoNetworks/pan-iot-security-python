from datetime import datetime, timedelta, timezone
import unittest

from . import mixin


class IotApiTest(mixin.Mixin, unittest.TestCase):
    def test_01(self):
        resp = self.api.alert(pagelength=0)
        self.assertEqual(resp.status_code, 400)

    def test_02(self):
        resp = self.api.alert(pagelength=1)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertIn(len(x['items']), (0, 1))

        total = x['total']
        resp = self.api.alert(offset=total)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        self.assertEqual(len(x['items']), 0)

        total_resolved = 0
        for ok, x in self.api.alerts_all(
                query_string={'resolved': 'yes'}):
            self.assertTrue(ok)
            total_resolved += 1
        total_unresolved = 0
        for ok, x in self.api.alerts_all(
                query_string={'resolved': 'no'}):
            self.assertTrue(ok)
            total_unresolved += 1
        self.assertEqual(total, total_resolved+total_unresolved,
                         'alert total != resolved+unresolved')

    def test_03(self):
        d = datetime.now(tz=timezone.utc) + timedelta(seconds=10)
        stime = d.strftime('%Y-%m-%dT%H:%M:%SZ')
        resp = self.api.alert(stime=stime)
        self.assertEqual(resp.status_code, 200)
        x = resp.json()
        t = resp.text
        msg = 'alerts in future stime %s: ' % stime
        msg += t
        self.assertEqual(x['total'], 0, msg)
        self.assertEqual(len(x['items']), 0, msg)
