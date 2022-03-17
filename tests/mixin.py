import asyncio
import json
import logging
import os

import paniot


class _MixinShared:
    def iotapi(self):
        path = os.getenv('PANIOT_KEYS')
        if path is None:
            raise RuntimeError('no PANIOT_KEYS in environment')
        with open(path, 'r') as f:
            x = json.load(f)
        kwargs = {
            'customerid': x['customerid'],
            'access_key_id': x['access-key-id'],
            'access_key': x['access-key'],
        }

        x = os.getenv('PANIOT_DEBUG')
        if x is not None:
            debug = int(x)
            logger = logging.getLogger()
            if debug == 3:
                logger.setLevel(paniot.DEBUG3)
            elif debug == 2:
                logger.setLevel(paniot.DEBUG2)
            elif debug == 1:
                logger.setLevel(paniot.DEBUG1)
            elif debug == 0:
                pass
            else:
                raise RuntimeError('PANIOT_DEBUG level must be 0-3')

            log_format = '%(message)s'
            handler = logging.StreamHandler()
            formatter = logging.Formatter(log_format)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return paniot.IotApi(**kwargs)


class Mixin(_MixinShared):
    def setUp(self):
        self.api = self.iotapi()

    def tearDown(self):
        self.api.session.close()


class AioMixin(_MixinShared):
    async def asyncSetUp(self):
        self.api = self.iotapi()

    async def asyncTearDown(self):
        await self.api.session.close()
        # XXX try to avoid "ResourceWarning: unclosed ..."
        await asyncio.sleep(0.1)
