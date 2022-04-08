..
 Copyright (c) 2022 Palo Alto Networks, Inc.

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

======
paniot
======

-----------------------------------------------------------
Python interface to the Palo Alto Networks IoT Security API
-----------------------------------------------------------

NAME
====

 paniot - Python interface to the Palo Alto Networks IoT Security
 API

SYNOPSIS
========
::

 import asyncio
 import json
 import sys

 import paniot


 async def iotapi():
     path = '/etc/iot/keys/keys-acmecorp.json'
     try:
         with open(path, 'r') as f:
             x = json.load(f)
     except (IOError, ValueError) as e:
         print('%s: %s' % (path, e), file=sys.stderr)
         sys.exit(1)

     kwargs = {
         'customerid': x['customerid'],
         'access_key_id': x['access-key-id'],
         'access_key': x['access-key'],
     }

     try:
         async with paniot.IotApi(**kwargs) as api:
             async for ok, x in api.devices_all():
	         if ok:
                     print(x)
                 else:
                     raise paniot.ApiError('%s: %s' % (
	                 x.status, x.reason))
     except (paniot.ApiError, paniot.ArgsError) as e:
         print('paniot.IotApi:', e, file=sys.stderr)
         sys.exit(1)

 asyncio.run(iotapi())

DESCRIPTION
===========

 The paniot module defines the IotApi class, which provides an
 interface to the Palo Alto Networks IoT Security API.

 IotApi provides an interface to the following IoT Security API requests:

 ================================   =====================   ================================
 Request                            IotApi Method           API Resource Path
 ================================   =====================   ================================
 Get device inventory               device()                /pub/v4.0/device/list
 Get device details by device ID    device_details()        /pub/v4.0/device
 Get device details by IP address   device_details()        /pub/v4.0/device/ip
 Get vulnerabilities                vulnerability()         /pub/v4.0/vulnerability/list
 Get security alerts                alert()                 /pub/v4.0/alert/list
 Get tags                           tag()                   /pub/v4.0/tag/list
 Update device tags                 device_update()         /pub/v4.0/device/update
 Update vulnerability               vuln_update()           /pub/v4.0/vulnerability/update
 Update alert                       alert_update()          /pub/v4.0/alert/update
 ================================   =====================   ================================

 Convenience methods implemented as generator functions are provided,
 which can be used to process all items when response paging can
 occur, and which will automatically retry requests when rate limiting
 occurs:

 =========================   ================================
 IotApi Method               API Resource Path
 =========================   ================================
 devices_all()               /pub/v4.0/device/list
 vulnerabilities_all()       /pub/v4.0/vulnerability/list
 alerts_all()                /pub/v4.0/alert/list
 =========================   ================================

 IotApi methods are implemented as both functions, and coroutines for
 use with the
 `asyncio library <https://docs.python.org/3/library/asyncio.html>`_.
 The class constructor will determine if there is a running
 event loop, and return a class implemented with or without coroutine
 methods.  The
 `aiohttp module <https://docs.aiohttp.org/>`_
 is used for asyncio HTTP requests, and the
 `requests module <https://docs.python-requests.org>`_
 is used for synchronous HTTP requests.

paniot Constants
----------------

 **__version__**
  paniot package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

 **DEFAULT_API_VERSION**
  Default API version.

paniot Constructor
------------------

class paniot.IotApi(\*, api_version=None, url=None, access_key_id=None, access_key=None, customerid=None, verify=None, timeout=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 **api_version**
  API version is a string in the form v\ **major**.\ **minor** or
  **major**.\ **minor** (e.g., *v4.0*).  The API version is used to determine
  the IotApi class implementation to use.

  The default API version is **DEFAULT_API_VERSION**.

  **api_version** is verified and the class attribute is set to an
  instance of the ApiVersion class (defined below).

 **url**
  URL used in API requests.  This should include the scheme and
  the IoT tenant specific domain name.  For example:
  "\https://acmecorp.iot.paloaltonetworks.com".

  The default is "\https://*customerid*.iot.paloaltonetworks.com".

 **access_key_id**
  ``X-Key-Id`` request header value used in API requests.  This is the
  *Access Key ID* value in the access key file that is downloaded when
  the API key is created.

 **access_key**
  ``X-Access-Key`` request header value used in API requests.  This is
  the *Secret Access Key* value in the access key file that is
  downloaded when the API key is created.

 **customerid**
  IoT customer ID (also known as tenant ID).

 **verify**
  Specify if SSL server certificate verification is performed.

  **verify** can be:

   a boolean

   a path to a file containing CA certificates to be used for SSL
   server certificate verification

  The default is to verify the server certificate.

 **timeout**
  Set client HTTP timeout values in seconds.

  **timeout** can be:

   a single value to set the total timeout (aiohttp) or the
   **connect** and **read** timeouts to the same value (requests)

   a tuple of length 2 to set the **connect** and **read** timeouts to
   different values (aiohttp and requests)

  The
  `aiohttp library timeout <https://docs.aiohttp.org/en/stable/client_quickstart.html#timeouts>`_
  defaults to a total timeout of 300 seconds, meaning the operation
  must complete within 5 minutes.

  The
  `requests library timeout <https://docs.python-requests.org/en/latest/user/advanced/#timeouts>`_
  defaults to no timeout, meaning the timeouts are determined by the
  operating system TCP implementation.

paniot Exceptions
-----------------

exception paniot.ApiError
~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the IotApi class when an API error occurs.  This
 can include for example an unexpected response document (JSON)
 format.

 All other exceptions are a subclass of ApiError, which can be
 used to catch any exception raised by the IotApi class.

exception paniot.ArgsError
~~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the IotApi class when an argument error occurs.
 This can include for example missing required arguments and invalid
 arguments.

 ArgsError is a subclass of ApiError.

The string representation of an instance of raised exceptions will
contain a user-friendly error message.

paniot.IotApi Method Return Value
---------------------------------

 IotApi class methods return the response object returned by the HTTP
 client library used for the request, or for generator functions, a
 generator object.

 For normal functions:

  The coroutine class methods use the
  `aiohttp library <https://docs.aiohttp.org/>`_
  and return a
  `ClientResponse object <https://docs.aiohttp.org/en/stable/client_reference.html#aiohttp.ClientResponse>`_.

  The normal class methods use the
  `requests library <https://docs.python-requests.org/>`_
  and return a
  `Response object <https://docs.python-requests.org/en/latest/api/#requests.Response>`_.

paniot.IotApi Methods
---------------------

device(\*, stime=None, detail=False, offset=None, pagelength=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``device()`` method performs the ``/device/list`` API
 request to get the devices in the IoT Security inventory.

 **stime**
  Start last activity time for devices to get as a limited form of an
  ISO 8601 timestamp.  The form is ``strftime('%Y-%m-%dT%H:%M:%SZ')``
  (e.g., **2022-01-19T00:31:47Z**).

 **detail**
  Return additional device fields.

 **offset**
  Numeric offset used for response paging.  The default offset is 0.

 **pagelength**
  Numeric number of items to return in a response.  The default
  page length is 1000.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and response JSON object fields
 are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-device-inventory.html>`__
 for the request.

devices_all(\*, stime=None, detail=False, query_string=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``devices_all()`` method is a generator function which executes
 the ``device()`` method with an offset starting at 0, a page length
 of 1000, and with retry enabled until all items are returned.  The
 generator function yields a tuple containing:

  **status**: a boolean

   - True: the HTTP status code of the request is 200
   - False: the HTTP status code of the request is not 200

  **response**: a response item, or HTTP client library response object

   - **status** is True: an object in the response ``devices`` list
   - **status** is False: HTTP client library response object

device_details(\*, deviceid=None, ip=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``device_details()`` method performs the ``/device`` API request
 when **deviceid** is specified, or the ``/device/ip`` API request
 when **ip** is specified.  Either **deviceid** or **ip** must be
 specified.  **deviceid** and **ip** cannot be specified at the same
 time.

 **deviceid**
  Get device details for the specified device ID.
  The device ID can be a MAC address or an IP address.

 **ip**
  Get device details for the specified IP address.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and response JSON object fields
 are defined in the API documentation for
 `device details by device ID
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-device-details-per-mac-address.html>`__
 and `device details by IP address
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-device-details-per-ip-address.html>`__.

vulnerability(\*, groupby=None, stime=None, deviceid=None, offset=None, pagelength=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``vulnerability()`` method performs the ``/vulnerability/list`` API
 request to get device vulnerabilities.

 **groupby**
  A string which specifies how to group the device vulnerabilities
  in the query results:

   **vulnerability** (default)
    Group results by vulnerability.  Each vulnerability and the device
    IDs (one or more) identified as vulnerable is an item in the items
    list.

   **device**
    Group results by device ID.  Each device ID and a single
    vulnerability (a vulnerability instance) is an item in the items
    list.

  Each **groupby** option uses a different JSON object structure
  in the response.
  The items list in the **vulnerability** object is
  ``response['items']['items']`` and in the **device** object is
  ``response['items']``.

 **stime**
  Start time for vulnerabilities to get as a limited form of an
  ISO 8601 timestamp.  The form is ``strftime('%Y-%m-%dT%H:%M:%SZ')``
  (e.g., **2022-01-19T00:31:47Z**).

 **deviceid**
  Get vulnerabilities for the specified device ID.
  The device ID can be a MAC address or an IP address.

  The default is to get vulnerabilities for all devices.

 **offset**
  Numeric offset used for response paging.  The default offset is 0.
  **offset** is ignored when **groupby** is **vulnerability**.

 **pagelength**
  Numeric number of items to return in a response.  The default
  page length is 1000.
  **pagelength** is ignored when **groupby** is **vulnerability**.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and response JSON object fields
 are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-vulnerability-instances.html>`__
 for the request.

vulnerabilities_all(\*, groupby=None, stime=None, query_string=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``vulnerabilities_all()`` method is a generator function which
 executes the ``vulnerability()`` method with an offset starting at 0,
 a page length of 1000, and with retry enabled until all items are
 returned.  The generator function yields a tuple containing:

  **status**: a boolean

   - True: the HTTP status code of the request is 200
   - False: the HTTP status code of the request is not 200

  **response**: a response item, or HTTP client library response object

   - **status** is True: an object in the response ``items`` list
   - **status** is False: HTTP client library response object

alert(\*, stime=None, offset=None, pagelength=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``alert()`` method performs the ``/alert/list`` API request to get
 security alerts.

 **stime**
  Start time for alerts to get as a limited form of an
  ISO 8601 timestamp.  The form is ``strftime('%Y-%m-%dT%H:%M:%SZ')``
  (e.g., **2022-01-19T00:31:47Z**).

 **offset**
  Numeric offset used for response paging.  The default offset is 0.

 **pagelength**
  Numeric number of items to return in a response.  The default
  page length is 1000.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and response JSON object fields
 are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-security-alerts.html>`__
 for the request.

alerts_all(\*, stime=None, query_string=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``alerts_all()`` method is a generator function which executes
 the ``alert()`` method with an offset starting at 0, a page length of
 1000, and with retry enabled until all items are returned.  The
 generator function yields a tuple containing:

  **status**: a boolean

   - True: the HTTP status code of the request is 200
   - False: the HTTP status code of the request is not 200

  **response**: a response item, or HTTP client library response object

   - **status** is True: an object in the response ``items`` list
   - **status** is False: HTTP client library response object

tag(\*, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``tag()`` method performs the ``/tag/list`` API request to get
 all custom tags.

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and response JSON object fields
 are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/get-list-of-user-defined-tags.html>`__
 for the request.

device_update(\*, json=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``device_update()`` method performs the ``/device/update`` API request
 to update tags assigned to IoT devices.

 **json**
  JSON text to send in the body of the request.

  **json** can be:

   a Python object that can be deserialized to JSON text

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and JSON object fields, and
 response JSON object fields are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/add-and-remove-user-defined-tags.html>`__
 for the request.

vuln_update(\*, json=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``vuln_update()`` method performs the ``/vulnerability/update`` API
 request to resolve a vulnerability.

 **json**
  JSON text to send in the body of the request.

  **json** can be:

   a Python object that can be deserialized to JSON text

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and JSON object fields, and
 response JSON object fields are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/resolve-vulnerability-instances.html>`__
 for the request.

alert_update(\*, id=None, json=None, query_string=None, retry=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``alert_update()`` method performs the ``/alert/update`` API request
 to resolve an alert.

 **id**
  Alert ID to update.  This is either a 12 character string, or a 24
  character string of hexadecimal symbols.

 **json**
  JSON text to send in the body of the request.

  **json** can be:

   a Python object that can be deserialized to JSON text

   a ``str``, ``bytes`` or ``bytearray`` type containing JSON text

 **query_string**
  Dictionary of key/value pairs to be sent as additional parameters in
  the query string of the request.  This can be used to specify API
  request parameters not supported by the class method.

 **retry**
  Retry the request indefinitely when a request is rate limited.  When
  a HTTP 429 status code is returned, the function will suspend
  execution for a period dependent on the rate limit of the API
  request, then retry the request.  Coroutine methods use
  ``asyncio.sleep()`` to suspend and normal methods use
  ``time.sleep()``.

 Additional request parameters and JSON object fields, and
 response JSON object fields are defined in the
 `API documentation
 <https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api/resolve-security-alert.html>`__
 for the request.

decode_jwt()
~~~~~~~~~~~~

 The ``decode_jwt()`` method decodes the access key, which is a
 `JSON Web Token (JWT)
 <https://www.rfc-editor.org/rfc/rfc7519.html>`_.
 The JWT is a
 `JSON Web Signature (JWS)
 <https://www.rfc-editor.org/rfc/rfc7515.html>`_.

 The JWS is a base64url encoded structure containing the following
 values:

 - header
 - payload
 - signature

 The method returns a tuple containing the header and payload JSON
 objects as Python objects.

paniot.IotApi Method Attributes
-------------------------------

 Methods that perform an API request store the API request rate limit
 and rate time window in method attributes:

 =================   ===========
 Attribute           Description
 =================   ===========
 window              time window in seconds
 rate_limit          maximum requests in time window
 =================   ===========

 The methods that store rate limit attributes are:

 - device()
 - device_details()
 - vulnerability()
 - alert()
 - tag()
 - device_update()
 - vuln_update()
 - alert_update()

 These attributes are used to determine the time to suspend execution
 when **retry** is used and a HTTP 429 status code is returned.  They
 are made available as method attributes for use in custom retry
 strategies.

paniot.ApiVersion class Attributes and Methods
----------------------------------------------

 The ApiVersion class provides an interface to the API version of the
 IotApi class instance.

 =================   ===========
 Attribute           Description
 =================   ===========
 major               major version as an integer
 minor               minor version as an integer
 =================   ===========

__str__()
~~~~~~~~~

 Major and minor version as a string in the format v\ **major**.\
 **minor** (e.g., *v1.0*).

__int__()
~~~~~~~~~

 Major and minor version as an integer with the following layout:

 ==================   ===========
 Bits (MSB 0 order)   Description
 ==================   ===========
 0-7                  unused
 8-15                 major version
 16-23                minor version
 24-31                reserved for future use
 ==================   ===========

Sample Usage
~~~~~~~~~~~~
::

 import json
 import sys

 import paniot


 def iotapi():
     path = '/etc/iot/keys/keys-acmecorp.json'
     try:
         with open(path, 'r') as f:
             x = json.load(f)
     except (IOError, ValueError) as e:
         print('%s: %s' % (path, e), file=sys.stderr)
         sys.exit(1)
     kwargs = {
         'customerid': x['customerid'],
         'access_key_id': x['access-key-id'],
         'access_key': x['access-key'],
     }

     try:
         api = paniot.IotApi(**kwargs)
     except (paniot.ApiError, paniot.ArgsError) as e:
         print('paniot.IotApi:', e, file=sys.stderr)
         sys.exit(1)
     print('api_version: %s, 0x%06x' %
           (api.api_version, int(api.api_version)))


 iotapi()

Debugging and Logging
---------------------

 The Python standard library ``logging`` module is used to log debug
 output; by default no debug output is logged.

 In order to obtain debug output the ``logging`` module must be
 configured: the logging level must be set to one of **DEBUG1**,
 **DEBUG2**, or **DEBUG3** and a handler must be configured.
 **DEBUG1** enables basic debugging output and **DEBUG2** and
 **DEBUG3** specify increasing levels of debug output.

 For example, to configure debug output to **stderr**:
 ::

  import logging

  if options['debug']:
      logger = logging.getLogger()
      if options['debug'] == 3:
          logger.setLevel(paniot.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(paniot.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(paniot.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

EXAMPLES
========

 The **iotapy.py** command line program calls each available IotApi
 method, with and without ``async/await``, and can be reviewed for
 sample usage of the class and its methods.
 ::

  $ iotapi.py -F /etc/iot/keys/keys-acmecorp.json --device --pagelength 1 -j
  device: 200 OK None
  {
      "devices": [
          {
              "allTags": [],
              "category": "Video Streaming",
              "confidence_score": 95,
              "deviceid": "84:ea:ed:92:87:f8",
              "hostname": "RokuStreamingStick",
              "ip_address": "172.25.1.117",
              "last_activity": "2022-01-22T19:56:42.000Z",
              "mac_address": "84:ea:ed:92:87:f8",
              "profile": "Roku Streaming Stick",
              "profile_type": "IoT",
              "profile_vertical": "Consumer IoT",
              "risk_level": "Low",
              "risk_score": 9,
              "tagIdList": []
          }
      ],
      "total": 1
  }

SEE ALSO
========

 iotapy.py command line program
  https://github.com/PaloAltoNetworks/pan-iot-security-python/blob/main/doc/iotapi.rst

 IoT Security API Reference
  https://docs.paloaltonetworks.com/iot/iot-security-api-reference.html

AUTHORS
=======

 Palo Alto Networks, Inc.
