pan-iot-security-python Tests
=============================

``pan-iot-security-python`` tests use the Python
`unit testing framework
<https://docs.python.org/3/library/unittest.html>`_.

An IoT Security tenant and its access key ID and access key are
required to run the tests.

The tests are read-only. Tests for the update API methods use only
test cases that should always result in an error.

Test Prerequisites
------------------

Place the customer ID, access key ID and access key in a JSON file
with the following object format:
::

  $ cat ~/.keys/keys-acmecorp.json
  {
      "customerid": "acmecorp",
      "access-key-id": "******",
      "access-key": "******"
  }

.. note:: Ensure the key file has strict file permissions (read/write
          for the owner and not accessible by group or other).

Then export the ``PANIOT_KEYS`` environment variable with the path to the
key file:
::

  $ export PANIOT_KEYS=~/.keys/keys-acmecorp.json

Run Tests
---------

To run all tests from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests -t .

To run a specific test from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests -t . -p test_noaio_constructor.py

To run all tests from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -s . -t ..

To run a specific test from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -s . -t .. -p test_noaio_constructor.py

asyncio and Normal Methods
--------------------------

Tests for the asyncio methods use the ``test_aio_`` prefix and for the
normal methods use the ``test_noaio_`` prefix.  asyncio method test
cases use the ``IsolatedAsyncioTestCase`` base class and the normal
methods use the ``TestCase`` base class.
