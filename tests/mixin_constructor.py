import paniot


class MixinConstructor:
    def test_01(self):
        kwargs = {}
        with self.assertRaises(paniot.ArgsError) as e:
            api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'customerid required')

    def test_02(self):
        kwargs = {
            'customerid': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'access_key_id required')

    def test_03(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            api = paniot.IotApi(**kwargs)
        self.assertEqual(str(e.exception), 'access_key required')

    def test_04(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
            'api_version': 'x',
        }
        with self.assertRaises(paniot.ArgsError) as e:
            api = paniot.IotApi(**kwargs)
        self.assertRegex(str(e.exception),
                         '^Invalid api_version')

    def test_05(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
        }
        api = paniot.IotApi(**kwargs)
        with self.assertRaises(paniot.ArgsError) as e:
            api.decode_jwt()
        self.assertEqual(str(e.exception),
                         'token is not a JSON Web Signature')

    def test_06(self):
        kwargs = {
            'customerid': 'x',
            'access_key_id': 'x',
            'access_key': 'x',
        }
        api = paniot.IotApi(**kwargs)
        for x in [api.device,
                  api.device_details,
                  api.vulnerability,
                  api.alert,
                  api.tag,
                  api.device_update,
                  api.vuln_update,
                  api.alert_update]:
            self.assertTrue(x.window > 0)
            self.assertTrue(x.rate_limit > 0)
