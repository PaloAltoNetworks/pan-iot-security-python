#
# Copyright (c) 2022 Palo Alto Networks, Inc.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import asyncio
from collections import namedtuple
from hashlib import blake2b
import logging
import re
import sys
import xml.etree.ElementTree as etree

__version__ = '0.3.0'

_default_api_version = (4, 0)
DEFAULT_API_VERSION = 'v%d.%d' % _default_api_version

DEBUG1 = logging.DEBUG
DEBUG2 = DEBUG1 - 1
DEBUG3 = DEBUG2 - 1

logging.addLevelName(DEBUG2, 'DEBUG2')
logging.addLevelName(DEBUG3, 'DEBUG3')


class ApiError(Exception):
    pass


class ArgsError(ApiError):
    pass


def panos_device_objects(*,
                         data=None,
                         format=None,
                         filter=None,
                         min_confidence=50,
                         dedup=True):
    def _name(x):
        data = str(sorted(x.items()))
        h = blake2b(data.encode(),
                    digest_size=15)
        return h.hexdigest()

    def normalize(x):
        # PAN-OS device dictionary does not allow & in fields and
        # normalizes to ' and '.
        for s in [' & ', ' &', '& ', '&']:
            x = x.replace(s, ' and ')
        return x

    keymap = {
        # IoT security  PAN-OS device-object
        'os_combined': 'os',
        'os_group':    'osfamily',
        'category':    'category',
        'profile':     'profile',
        'model':       'model',
        'vendor':      'vendor',
    }

    if format not in ['set', 'xml', 'xml2', 'xml3']:
        raise ArgsError('invalid format: "%s"' % format)

    if filter is not None and filter:
        if not isinstance(filter, list):
            raise ArgsError('filter not list')
        for x in filter:
            if x not in keymap.values():
                raise ArgsError('invalid filter item: "%s"' % x)
        new = {}
        for k, v in keymap.items():
            if v in filter:
                new[k] = keymap[k]
        if not new:
            raise ArgsError('all keys filtered')
        keymap = new

    panos_objects = []
    if data is None:
        return panos_objects
    if not isinstance(data, list):
        raise ArgsError('data not list')

    for obj in data:
        if not isinstance(obj, dict):
            raise ArgsError('data item not dict')

        # Skip object when confidence score not > 50; the PAN-OS
        # device dictionary doesn't store these profiles.
        if ('confidence_score' in obj and
           not obj['confidence_score'] > min_confidence):
            continue

        x = {}
        for key in keymap:
            if key in obj and obj[key]:
                # Skip os_combined with no version; the PAN-OS device
                # dictionary doesn't store these.
                if (key == 'os_combined' and
                    ('os/firmware_version' not in obj or
                     not obj['os/firmware_version'])):
                    continue
                x[keymap[key]] = normalize(obj[key])

        if x:
            if 'vertical' in obj:
                x['description'] = obj['vertical']
            if not dedup and 'deviceid' in obj:
                x['description'] = obj['deviceid']
            panos_objects.append(x)

    if dedup:
        new = []
        for i in range(len(panos_objects)):
            if panos_objects[i] not in panos_objects[i+1:]:
                new.append(panos_objects[i])
        panos_objects = new

    if format == 'set':
        prefix = 'set device-object %s %s "%s"'
        objects_set = []
        for obj in panos_objects:
            x = []
            name = _name(obj)
            for key in obj:
                x.append(prefix % (name, key, obj[key]))
            objects_set.append('\n'.join(x))

        return objects_set

    if format == 'xml':
        root = etree.Element('device-object')
        for obj in panos_objects:
            name = _name(obj)
            entry = etree.SubElement(root, 'entry',
                                     {'name': name})
            for key in obj:
                member = etree.SubElement(entry, key)
                if key == 'description':
                    member.text = obj[key]
                else:
                    etree.SubElement(member, 'member').text = obj[key]

        return [root]

    if format in ['xml2', 'xml3']:  # XXX
        # action=multi-config document
        if format == 'xml2':
            # firewall
            xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                     "/vsys/entry[@name='vsys1']/device-object")
        elif format == 'xml3':
            # Panorama
            xpath = '/config/shared/device-object'

        id = 0
        root = etree.Element('multi-config')
        for obj in panos_objects:
            id += 1
            action = etree.SubElement(root, 'set',
                                      {'id': str(id),
                                       'xpath': xpath})
            name = _name(obj)
            entry = etree.SubElement(action, 'entry',
                                     {'name': name})
            for key in obj:
                member = etree.SubElement(entry, key)
                if key == 'description':
                    member.text = obj[key]
                else:
                    etree.SubElement(member, 'member').text = obj[key]

        return [root]


class ApiVersion(namedtuple('api_version',
                            ['major', 'minor'])):
    def __str__(self):
        return 'v%d.%d' % (self.major, self.minor)

    def __int__(self):
        # reserve lower 8 bits for 'future' use
        return self.major << 16 | self.minor << 8


def _isaio():
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


def IotApi(api_version=None, *args, **kwargs):
    _log = logging.getLogger(__name__).log

    if api_version is None:
        x = _default_api_version
    else:
        r = re.search(r'^v?(\d+)\.(\d+)$', api_version)
        if r is None:
            raise ArgsError('Invalid api_version: %s' % api_version)
        x = int(r.group(1)), int(r.group(2))
    _api_version = ApiVersion(*x)
    _log(DEBUG1, 'api_version: %s, 0x%06x',
         _api_version, int(_api_version))

    package = 'paniot'
    name = 'aioapi' if _isaio() else 'api'
    module = 'v%d_%d%s' % (_api_version.major,
                           _api_version.minor,
                           name)
    module_name = '%s.%s' % (package, module)
    class_ = 'IotApi'

    try:
        __import__(module_name)
    except ImportError as e:
        raise ArgsError('Module import error: %s: %s' %
                        (module_name, e))

    try:
        klass = getattr(sys.modules[module_name], class_)
    except AttributeError:
        raise ArgsError('Class not found: %s' % class_)

    return klass(api_version=_api_version, *args, **kwargs)
