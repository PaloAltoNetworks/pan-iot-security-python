import asyncio
import unittest

import paniot
from . import mixin_constructor


class IotApiTest(unittest.IsolatedAsyncioTestCase,
                 mixin_constructor.MixinConstructor):
    async def test_00(self):
        asyncio.get_running_loop()
