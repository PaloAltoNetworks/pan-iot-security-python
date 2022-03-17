import asyncio
import unittest

import paniot
from . import mixin_constructor


class IotApiTest(unittest.TestCase,
                 mixin_constructor.MixinConstructor):
    def test_00(self):
        self.assertRaises(RuntimeError, asyncio.get_running_loop)
