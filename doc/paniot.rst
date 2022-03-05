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

=========
iotapi.py
=========

-----------------------------------------------------------------
command line interface to the Palo Alto Networks IoT Security API
-----------------------------------------------------------------

NAME
====

 iotapi.py - command line interface to the Palo Alto Networks IoT Security API

SYNOPSIS
========
::

 iotapi.py [options]
    --url url                IoT tenant ID URL
    --access-key-id id       API access key ID
    --access-key token       API access key
    --customerid id          IoT tenant customer ID
    --device                 get device inventory or details API request
    --devices                get all device inventory
    --detail                 detail=true for device inventory request
    --stime time             start last activity time
                             -time for relative to now
                             -seconds or -num{s|m|h|d|w}
    --deviceid id            get device by device ID
    --ip ip                  get device by IP address
    --vuln                   get vulnerability API request
    --groupby group          groupby parameter for vulnerability request:
                             vulnerability|device (default: vulnerability)
    --vulns                  get all vulnerabilities
    --alert                  get security alert API request
    --alerts                 get all security alerts
    --tag                    get tag API request
    --offset num             items offset
    --pagelength num         number of items to return
    --device-update          update device API request
    --vuln-update            update vulnerability API request
    --alert-update           update alert API request
    --id id                  alert ID
    -R json                  JSON request (multiple -R's allowed)
    -Q json                  URL query string (multiple -Q's allowed)
    --verify opt             SSL server verify option: yes|no|path
    --aio                    Use asyncio (default)
    --noaio                  Don't use asyncio
    --api-version version    IoT API version (default v4.0)
    -j                       print JSON
    -p                       print Python
    -J expression            JMESPath expression for JSON response data
    --jwt                    print header, payload from JWT (access key)
    --timeout timeout        connect, read timeout
    -F path                  JSON options (multiple -F's allowed)
    --debug level            debug level (0-3)
    --dtime                  add time string to debug output
    --version                display version
    --help                   display usage

DESCRIPTION
===========

 **iotapi.py** is used to perform IoT Security API requests.  It uses
 the IotApi class from the **paniot.api** module to execute API
 requests.

 The IoT Security API can be used to:

 - Get device inventory
 - Get device details by device ID
 - Get device details by IP address
 - Get vulnerabilities
 - Get security alerts
 - Get tags
 - Update device tags
 - Update vulnerabilities
 - Update alerts

 The options are:

 ``--url`` *url*
  URL used in API requests.  This should include the scheme and
  the IoT tenant specific domain name.  For example:
  "\https://acmecorp.iot.paloaltonetworks.com".

  The default is "\https://*customerid*.iot.paloaltonetworks.com".

 ``--access-key-id`` *id*
  ``X-Key-Id`` request header value used in API requests.  This is the
  *Access Key ID* value in the access key file that is downloaded when
  the API key is created.

 ``--access-key`` *token*
  ``X-Access-Key`` request header value used in API requests.  This is
  the *Secret Access Key* value in the access key file that is
  downloaded when the API key is created.

 ``--customerid`` *id*
  IoT customer ID (also known as tenant ID).

 ``--device``
  Perform the ``/device/list``, ``/device`` or ``/device/ip`` API
  request.

  When used with ``--ip`` the ``/device/ip`` request is performed to
  get the device details for the specified IP address.

  When used with ``--deviceid`` the ``/device`` API request is
  performed to get the device details for the specified device ID.

  When ``--ip`` or ``--deviceid`` are not specified, the
  ``/device/list`` API request is performed to get the devices in the
  IoT Security inventory.

 ``--devices``
  Get all devices in the IoT Security inventory.  This uses the IotAPI
  ``devices_all()`` method which performs the ``/device/list`` API
  request until all items are returned.

  The resulting object contains a *things* name, and the value is an
  array of device objects.

 ``--detail``
  Sets ``detail=true`` in the the device inventory API request query
  string.

 ``--stime`` *time*
  Sets the ``stime`` (start last activity time) argument in the API
  request query string.  The API requests that allow start time are:

  - Get device inventory
  - Get device details by device ID
  - Get device details by IP address
  - Get vulnerabilities
  - Get security alerts

  Start time can be a limited form of an ISO 8601 timestamp or a
  time relative to the current time.

  The ISO 8601 timestamp form is ``strftime('%Y-%m-%dT%H:%M:%SZ')``
  (e.g., **2022-01-19T00:31:47Z**).

  The start time can be specified relative to the current time using
  negative seconds, or using a negative time value followed by a unit
  specifier.

  ==============  ====
  Unit Specifier  Unit
  ==============  ====
  *None*          Seconds
  **s** or **S**  Seconds
  **m** or **M**  Minutes
  **h** or **H**  Hours
  **d** or **D**  Days
  **w** or **W**  Weeks
  ==============  ====

 ``--deviceid`` *id*
  Perform the ``/device`` API request to get the device details for
  the specified device ID.  The device ID can be a MAC address or an
  IP address.

 ``--ip`` *ip*
  Perform the ``/device/ip`` API request to get the device details for
  the specified IP address.

 ``--vuln``
  Perform the ``/vulnerability/list`` API request to get device
  vulnerabilities.

 ``--groupby`` *group*
  Specify how to group the device vulnerabilities in the query
  results:

   **vulnerability** (default)
    Group results by vulnerability.  Each vulnerability and the device
    IDs (one or more) identified as vulnerable is an item in the items
    list.

   **device**
    Group results by device ID.  Each device ID and a single
    vulnerability (a vulnerability instance) is an item in the items
    list.

 ``--vulns``
  Get all vulnerabilities.  This uses the IotAPI
  ``vulnerabilities_all()`` method which performs the
  ``/vulnerability/list`` API request until all items are returned.

  The resulting object contains a *things* name, and the value is an
  array of vulnerability objects.

 ``--alert``
  Perform the ``/alert/list`` API request to get security alerts.

 ``--alerts``
  Get all alerts.  This uses the IotAPI ``alerts_all()`` method which
  performs the ``/alert/list`` API request until all items are
  returned.

  The resulting object contains a *things* name, and the value is an
  array of alert objects.

 ``--tag``
  Perform the ``/tag/list`` API request to get all custom tags.

 ``--offset`` *num*
  Numeric offset used for response paging.  The default offset is 0.

 ``--pagelength`` *num*
  Numeric number of items to return in a response.  The default
  page length is 1000.

 ``--device-update``
  Perform the ``/device/update`` API request to update tags assigned
  to IoT devices.

 ``--vuln-update``
  Perform the ``/vulnerability/update`` API request to resolve a
  vulnerability.

 ``--alert-update``
  Perform the ``/alert/update`` API request to resolve an alert.

 ``--id`` *id*
  Alert ID to update.  This is either a 12 character string, or a 24
  character string of hexadecimal symbols.

 ``-R`` *json*
  Specify a JSON object to use as the body of the POST request.
  Multiple instances of the option is allowed.  The API requests
  that use POST are:

  ========================  ===================  =================
  Operation                 Option               API Resource Path
  ========================  ===================  =================
  Update device tags        ``--device-update``  /pub/v4.0/device/update
  Update vulnerabilities    ``--vuln-update``    /pub/v4.0/vulnerability/update
  Update alerts             ``--alert-update``   /pub/v4.0/alert/update
  ========================  ===================  =================

  *json* can be a string, a path to a file containing a JSON object,
  or the value **-** to specify a JSON object is on *stdin*.

 ``-Q`` *json*
  Specify a JSON object to modify the query string used in the
  request.  This can be used to specify request parameters that are
  not supported by a class method or the command line interface.
  Multiple instances of the option is allowed.

  *json* can be a string, a path to a file containing a JSON object,
  or the value **-** to specify a JSON object is on *stdin*.

 ``--verify`` *opt*
  Specify the type of SSL server certificate verification to be
  performed:

   **yes**
    Perform SSL server certificate verification.  This is the default.

   **no**
    Disable SSL server certificate verification.

   ``path``
    Path to a file containing CA certificates to be used for SSL
    server certificate verification.

 ``--aio``
  Use the `asyncio <https://docs.python.org/3/library/asyncio.html>`_
  class interface.  This is the default.

  The asyncio class interface uses the
  `aiohttp library <https://docs.aiohttp.org/>`_.

 ``--noaio``
  Use the normal class interface.

  The normal class interface uses the
  `requests library <https://docs.python-requests.org/>`_.

 ``--api-version`` *api_version*
  API version is a string in the form v\ **major**.\ **minor** or
  **major**.\ **minor** (e.g., *v4.0*).  The API version is used to determine
  the IotApi class implementation to use.

  The default API version can be displayed with ``iotapi.py --debug 1``.

 ``-j``
  Print JSON response to *stdout*.

 ``-p``
  Print JSON response in Python to *stdout*.

 ``-J`` *expression*
  `JMESPath expression
  <https://jmespath.org/>`_ to evaluate on the response JSON object.
  This requires the `jmespath package
  <https://pypi.org/project/jmespath/>`_.

 ``--jwt``
  Decode the access key, which is a JSON Web Token (JWT), and print
  the header and payload JSON objects.

 ``--timeout`` *timeout*
  Set client HTTP timeout values in seconds.

  **timeout** can be:

   a single value to set the total timeout (aiohttp) or the
   **connect** and **read** timeouts to the same value (requests)

   a tuple of length 2 to set the **connect** and **read** timeouts to
   different values (aiohttp and requests)

  The
  `asyncio library timeout
  <https://docs.aiohttp.org/en/stable/client_quickstart.html#timeouts>`_
  defaults to a total timeout of 300 seconds, meaning the operation
  must complete within 5 minutes.

  The
  `requests library timeout
  <https://docs.python-requests.org/en/latest/user/advanced/#timeouts>`_
  defaults to no timeout, meaning the timeouts are determined by the
  operating system TCP implementation.

 ``-F`` *path*
  Path to file containing a JSON a object with command options.  The allowed
  options are:

  - ``api-version``
  - ``access-key-id``
  - ``access-key``
  - ``customerid``

  Because this file may contain the access key it should have strict
  file permissions (read/write for the owner and not accessible by
  group or other).

 ``--debug`` *level*
  Enable debugging in **iotapi.py** and the **paniot.api** module.
  *level* is an integer in the range 0-3; 0 specifies no
  debugging and 3 specifies maximum debugging.

 ``--dtime``
  Prefix debug output with a timestamp.

 ``--version``
  Display version.

 ``--help``
  Display command options.

EXIT STATUS
===========

 **paniot.py** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 The examples use a JSON config file containing the customer ID and
 access keys:
 ::

  $ cat ~/.keys/keys-acmecorp.json
  {
      "customerid": "acmecorp",
      "access-key-id": "******",
      "access-key": "******"
  }

 Get a single device:
 ::

  $ iotapi.py -F ~/.keys/keys-acmecorp.json --debug 1 --device --pagelength 1 -j
  Using selector: KqueueSelector
  api_version: v4.0, 0x040000
  GET https://acmecorp.iot.paloaltonetworks.com/pub/v4.0/device/list?customerid=acmecorp&pagelength=1 200 OK None
  device: 200 OK None
  {
      "devices": [
          {
              "allTags": [],
              "category": "Entertainment",
              "confidence_score": 99,
              "deviceid": "20:ef:bd:8b:67:1d",
              "hostname": "RokuUltra",
              "ip_address": "172.25.1.127",
              "last_activity": "2022-03-04T17:06:25.646Z",
              "mac_address": "20:ef:bd:8b:67:1d",
              "profile": "Roku Device",
              "profile_type": "IoT",
              "profile_vertical": "Office",
              "risk_level": "Low",
              "risk_score": 10,
              "tagIdList": []
          }
      ],
      "total": 1
  }
  closing aiohttp session

 Get all devices in the inventory and use a JMESPath search expression to
 identify Roku devices:
 ::

  $ iotapi.py -F ~/.keys/keys-acmecorp.json -j --device --detail -J "devices[?os_group=='Roku OS'].[deviceid,hostname,ip_address]"
  device: 200 OK None
  [
      [
          "84:ea:ed:92:87:f8",
          "RokuStreamingStick",
          "172.25.1.117"
      ],
      [
          "84:ea:ed:91:ce:72",
          "RokuStreamingStickKevin",
          "172.25.1.143"
      ],
      [
          "20:ef:bd:8b:67:1d",
          "RokuUltra",
          "172.25.1.127"
      ]
  ]

 Get devices with activity in the last 2 hours:
 ::

  $ iotapi.py -F ~/.keys/keys-acmecorp.json --debug 1 -j --device --stime -2h
  Using selector: KqueueSelector
  api_version: v4.0, 0x040000
  GET https://acmecorp.iot.paloaltonetworks.com/pub/v4.0/device/list?customerid=acmecorp&stime=2022-03-05T17:27:05Z 200 OK None
  device: 200 OK None
  {
      "devices": [
          {
              "allTags": [],
              "category": "Digital Signage",
              "confidence_score": 99,
              "deviceid": "d8:a3:5c:54:9e:29",
              "hostname": "Samsung",
              "ip_address": "172.25.1.134",
              "last_activity": "2022-03-05T17:35:47.646Z",
              "mac_address": "d8:a3:5c:54:9e:29",
              "profile": "Samsung Signage TV",
              "profile_type": "IoT",
              "profile_vertical": "Office",
              "risk_level": "Low",
              "risk_score": 10,
              "tagIdList": []
          }
      ],
      "total": 1
  }
  closing aiohttp session

 Get device details by IP address (can be multiple devices):
 ::

  $ iotapi.py -F ~/.keys/keys-acmecorp.json -j --device --ip 172.25.1.143 | tail
  device_details: 200 OK None
              "source": "",
              "subnet": "172.25.1.0/24",
              "tagIdList": [],
              "vendor": "Roku, Inc.",
              "vlan": "",
              "wire_or_wireless": null
          }
      ],
      "total": 3
  }

 Get unresolved alerts:
 ::

  $ iotapi.py -F ~/.keys/keys-acmecorp.json -j --alert \
  > -J "items[?resolved=='no'].[id,deviceid,profile,date,severity,type,name,description]"
  alert: 200 OK None
  [
      [
          "61de59cf49bd6a08000b6a1e",
          "38:94:ed:4d:4d:15",
          "Netgear Device",
          "2022-01-12T04:31:12.000Z",
          "info",
          "policy_alert",
          "Risky application usage by IoT device",
          "The usage of droidvpn is a security risk based on certain attributes.  For example, this application may be used by existing malware, utilize excessive bandwidth, or have existing vulnerabilities.  Refer to the applications page to find more information on this specific application."
      ]
  ]

 Resolve (update) alert:
 ::

  $ cat alert-update.json
  {
      "reason": "false positive",
      "reason_type": [
          "No Action Needed"
      ],
      "resolved": "yes"
  }

  $ iotapi.py -F ~/.keys/keys-acmecorp.json --alert-update \
  > --id 61de59cf49bd6a08000b6a1e -R alert-update.json
  alert-update: 200 OK None

SEE ALSO
========

 paniot.api

 IoT Security API Reference
  https://docs.paloaltonetworks.com/iot/iot-security-api-reference.html

 JMESPath query language for JSON
  https://jmespath.org/

AUTHORS
=======

 Palo Alto Networks, Inc.
