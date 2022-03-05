#!/usr/bin/env python3

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
import copy
from datetime import datetime, timedelta, timezone
import getopt
import json
import logging
import os
import pprint
import sys
try:
    import jmespath
    have_jmespath = True
except ImportError:
    have_jmespath = False

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]


from paniot import (IotApi, ArgsError, DEBUG1, DEBUG2, DEBUG3,
                    DEFAULT_API_VERSION, __version__)

INDENT = 4


def main():
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(DEBUG1)

        log_format = '%(message)s'
        if options['dtime']:
            log_format = '%(asctime)s ' + log_format
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    kwargs = {}
    for x in ['api-version', 'url',
              'customerid', 'access-key-id', 'access-key',
              'verify', 'timeout']:
        if options[x] is not None:
            k = x.replace('-', '_')
            kwargs[k] = options[x]

    try:
        if options['aio']:
            asyncio.run(aioapi_request(kwargs, options))
        else:
            api_request(kwargs, options)
    except KeyboardInterrupt:
        sys.exit(0)


def api_request(kwargs, options):
    try:
        with IotApi(**kwargs) as api:
            request(api, options)

    except Exception as e:
        print('%s: %s' % (e.__class__.__name__, e),
              file=sys.stderr)
        sys.exit(1)


async def aioapi_request(kwargs, options):
    try:
        async with IotApi(**kwargs) as api:
            await aiorequest(api, options)

    except Exception as e:
        print('%s: %s' % (e.__class__.__name__, e),
              file=sys.stderr)
        sys.exit(1)


def request(api, options):
    if options['print_jwt']:
        print_jwt(api)
        sys.exit(0)

    if options['device']:
        if options['deviceid'] is not None or options['ip'] is not None:
            resp = api.device_details(
                deviceid=options['deviceid'],
                ip=options['ip'],
                query_string=options['query_string_obj'])
            print_status('device_details', resp)
            print_response(options, resp)
            resp.raise_for_status()
        else:
            resp = api.device(
                stime=options['stime'],
                detail=options['detail'],
                offset=options['offset'],
                pagelength=options['pagelength'],
                query_string=options['query_string_obj'])
            print_status('device', resp)
            print_response(options, resp)
            resp.raise_for_status()

    elif options['devices']:
        kwargs = {
            'stime': options['stime'],
            'detail': options['detail'],
            'query_string': options['query_string_obj'],
        }

        wrap_obj(options, api.devices_all, **kwargs)

    elif options['vuln']:
        if options['deviceid'] and options['ip']:
            print('--vuln device lookup is by deviceid or ip; both specified',
                  file=sys.stderr)
            sys.exit(1)

        kwargs = {}
        if options['deviceid'] is not None:
            kwargs['deviceid'] = options['deviceid']
        if options['ip'] is not None:
            kwargs['deviceid'] = options['ip']

        resp = api.vulnerability(
            groupby=options['groupby'],
            stime=options['stime'],
            offset=options['offset'],
            pagelength=options['pagelength'],
            query_string=options['query_string_obj'],
            **kwargs)
        print_status('vulnerability', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['vulns']:
        kwargs = {
            'groupby': options['groupby'],
            'stime': options['stime'],
            'query_string': options['query_string_obj'],
        }

        wrap_obj(options, api.vulnerabilities_all, **kwargs)

    elif options['alert']:
        resp = api.alert(
            stime=options['stime'],
            offset=options['offset'],
            pagelength=options['pagelength'],
            query_string=options['query_string_obj'])
        print_status('alert', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['alerts']:
        kwargs = {
            'stime': options['stime'],
            'query_string': options['query_string_obj'],
        }

        wrap_obj(options, api.alerts_all, **kwargs)

    elif options['tag']:
        resp = api.tag(query_string=options['query_string_obj'])
        print_status('tag', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['device-update']:
        resp = api.device_update(
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('device-update', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['vuln-update']:
        resp = api.vuln_update(
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('vuln-update', resp)
        print_response(options, resp)
        resp.raise_for_status()

    elif options['alert-update']:
        resp = api.alert_update(
            id=options['id'],
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('alert-update', resp)
        print_response(options, resp)
        resp.raise_for_status()


async def aiorequest(api, options):
    if options['print_jwt']:
        print_jwt(api)
        sys.exit(0)

    if options['device']:
        if options['deviceid'] is not None or options['ip'] is not None:
            resp = await api.device_details(
                deviceid=options['deviceid'],
                ip=options['ip'],
                query_string=options['query_string_obj'])
            print_status('device_details', resp)
            await aioprint_response(options, resp)
            resp.raise_for_status()
        else:
            resp = await api.device(
                stime=options['stime'],
                detail=options['detail'],
                offset=options['offset'],
                pagelength=options['pagelength'],
                query_string=options['query_string_obj'])
            print_status('device', resp)
            await aioprint_response(options, resp)
            resp.raise_for_status()

    elif options['devices']:
        kwargs = {
            'stime': options['stime'],
            'detail': options['detail'],
            'query_string': options['query_string_obj'],
        }

        await aiowrap_obj(options, api.devices_all, **kwargs)

    elif options['vuln']:
        if options['deviceid'] and options['ip']:
            print('--vuln device lookup is by deviceid or ip; both specified',
                  file=sys.stderr)
            sys.exit(1)

        kwargs = {}
        if options['deviceid'] is not None:
            kwargs['deviceid'] = options['deviceid']
        if options['ip'] is not None:
            kwargs['deviceid'] = options['ip']

        resp = await api.vulnerability(
            groupby=options['groupby'],
            stime=options['stime'],
            offset=options['offset'],
            pagelength=options['pagelength'],
            query_string=options['query_string_obj'],
            **kwargs)
        print_status('vulnerability', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['vulns']:
        kwargs = {
            'groupby': options['groupby'],
            'stime': options['stime'],
            'query_string': options['query_string_obj'],
        }

        await aiowrap_obj(options, api.vulnerabilities_all, **kwargs)

    elif options['alert']:
        resp = await api.alert(
            stime=options['stime'],
            offset=options['offset'],
            pagelength=options['pagelength'],
            query_string=options['query_string_obj'])
        print_status('alert', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['alerts']:
        kwargs = {
            'stime': options['stime'],
            'query_string': options['query_string_obj'],
        }

        await aiowrap_obj(options, api.alerts_all, **kwargs)

    elif options['tag']:
        resp = await api.tag(query_string=options['query_string_obj'])
        print_status('tag', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['device-update']:
        resp = await api.device_update(
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('device-update', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['vuln-update']:
        resp = await api.vuln_update(
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('vuln-update', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()

    elif options['alert-update']:
        resp = await api.alert_update(
            id=options['id'],
            json=options['json_request_obj'],
            query_string=options['query_string_obj'])
        print_status('alert-update', resp)
        await aioprint_response(options, resp)
        resp.raise_for_status()


def wrap_obj(options, func, **kwargs):
    obj = {
        'things': []
    }

    wrap = True
    # XXX default to False with option to enable?
    for x in func(**kwargs):
        if wrap:
            obj['things'].append(x)
        else:
            print_json_response(options, x)
    if wrap:
        print_json_response(options, obj)


async def aiowrap_obj(options, func, **kwargs):
    obj = {
        'things': []
    }

    wrap = True
    # XXX default to False with option to enable?
    async for x in func(**kwargs):
        if wrap:
            obj['things'].append(x)
        else:
            print_json_response(options, x)
    if wrap:
        print_json_response(options, obj)


def print_jwt(api):
    try:
        header, payload = api.decode_jwt()
    except ArgsError as e:
        print('JWT error:', e, file=sys.stderr)
        sys.exit(1)

    print(json.dumps(header, sort_keys=True, indent=INDENT))
    print(json.dumps(payload, sort_keys=True, indent=INDENT))
    sys.exit(0)


def print_status(name, resp):
    print('%s:' % name, end='', file=sys.stderr)
    if hasattr(resp, 'status'):
        if resp.status is not None:
            print(' %d' % resp.status, end='', file=sys.stderr)
    elif hasattr(resp, 'status_code'):
        if resp.status_code is not None:
            print(' %d' % resp.status_code, end='', file=sys.stderr)
    if resp.reason is not None:
        print(' %s' % resp.reason, end='', file=sys.stderr)
    if resp.headers is not None:
        print(' %s' % resp.headers.get('content-length'),
              end='', file=sys.stderr)
    print(file=sys.stderr)


def print_response(options, resp):
    content_type = resp.headers.get('content-type')
    if (content_type is not None and
       content_type.startswith('application/json')):
        x = resp.json()
        print_json_response(options, x)
    else:
        print(resp.text)


async def aioprint_response(options, resp):
    if resp.content_type == 'application/json':
        x = await resp.json()
        print_json_response(options, x)
    else:
        print(await resp.text())


def print_json_response(options, x):
    if options['jmespath'] is not None:
        try:
            x = jmespath.search(options['jmespath'], x)
        except jmespath.exceptions.JMESPathError as e:
            print('JMESPath %s: %s' % (e.__class__.__name__, e),
                  file=sys.stderr)
            sys.exit(1)

    if options['print_python']:
        print(pprint.pformat(x))

    if options['print_json']:
        print(json.dumps(x, sort_keys=True, indent=INDENT))


def process_arg(arg):
    stdin_char = '-'

    if arg == stdin_char:
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(arg)
            lines = f.readlines()
            f.close()
        except IOError:
            lines = [arg]

    lines = ''.join(lines)
    return lines


def process_time(x):
    def nice_time(time):
        import re

        m = re.match(r'^-(\d+)([sSmMhHdDwW]?)$', time)
        if not m:
            raise ValueError('Invalid time: %s' % time)

        kwargs = {}
        x = m.groups()
        modifier = x[1].lower()
        if modifier == '' or modifier == 's':
            kwargs['seconds'] = int(x[0])
        elif modifier == 'm':
            kwargs['minutes'] = int(x[0])
        elif modifier == 'h':
            kwargs['hours'] = int(x[0])
        elif modifier == 'd':
            kwargs['days'] = int(x[0])
        elif modifier == 'w':
            kwargs['weeks'] = int(x[0])
        else:
            assert False, 'unhandled modifier: %s' % modifier

        try:
            t = timedelta(**kwargs)
        except OverflowError as e:
            raise OverflowError('Invalid time: %s: %s' % (time, e))

        return t

    try:
        t = nice_time(x)
    except OverflowError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except ValueError:
        return x
    else:
        d = datetime.now(tz=timezone.utc) - t
        return d.strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_opts():
    def opt_verify(x):
        if x == 'yes':
            return True
        elif x == 'no':
            return False
        elif os.path.exists(x):
            return x
        else:
            print('Invalid --verify option:', x, file=sys.stderr)
            sys.exit(1)

    options = {
        'config': {},
        'api-version': None,
        'url': None,
        'access-key-id': None,
        'access-key': None,
        'customerid': None,
        'device': False,
        'devices': False,
        'detail': False,
        'stime': None,
        'deviceid': None,
        'ip': None,
        'vuln': False,
        'groupby': None,
        'vulns': False,
        'alert': False,
        'alerts': False,
        'tag': False,
        'offset': None,
        'pagelength': None,
        'device-update': False,
        'vuln-update': False,
        'alert-update': False,
        'id': None,
        'json_requests': [],
        'json_request_obj': None,
        'query_strings': [],
        'query_string_obj': None,
        'verify': None,
        'aio': True,
        'print_json': False,
        'print_python': False,
        'print_jwt': False,
        'jmespath': None,
        'timeout': None,
        'debug': 0,
        'dtime': False,
        }

    short_options = 'F:J:jpQ:R:'
    long_options = [
        'help', 'version', 'debug=', 'dtime',
        'api-version=', 'url=',
        'access-key-id=', 'access-key=', 'customerid=',
        'device', 'devices', 'detail', 'stime=',
        'deviceid=', 'ip=',
        'vuln', 'groupby=', 'vulns',
        'alert', 'alerts',
        'tag',
        'offset=', 'pagelength=',
        'device-update', 'vuln-update', 'alert-update',
        'id=',
        'verify=', 'aio', 'noaio',
        'jwt', 'timeout=',
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '-F':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    options['config'].update(x)
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--api-version':
            options['api-version'] = arg
        elif opt == '--url':
            options['url'] = arg
        elif opt == '--access-key-id':
            options['access-key-id'] = arg
        elif opt == '--access-key':
            options['access-key'] = arg
        elif opt == '--customerid':
            options['customerid'] = arg
        elif opt == '--device':
            options['device'] = True
        elif opt == '--devices':
            options['devices'] = True
        elif opt == '--detail':
            options['detail'] = True
        elif opt == '--stime':
            options['stime'] = process_time(arg)
        elif opt == '--deviceid':
            options['deviceid'] = arg
        elif opt == '--ip':
            options['ip'] = arg
        elif opt == '--vuln':
            options['vuln'] = True
        elif opt == '--groupby':
            options['groupby'] = arg
        elif opt == '--vulns':
            options['vulns'] = True
        elif opt == '--alert':
            options['alert'] = True
        elif opt == '--alerts':
            options['alerts'] = True
        elif opt == '--tag':
            options['tag'] = True
        elif opt == '--offset':
            options['offset'] = arg
        elif opt == '--pagelength':
            options['pagelength'] = arg
        elif opt == '--device-update':
            options['device-update'] = True
        elif opt == '--vuln-update':
            options['vuln-update'] = True
        elif opt == '--alert-update':
            options['alert-update'] = True
        elif opt == '--id':
            options['id'] = arg
        elif opt == '-R':
            options['json_requests'].append(process_arg(arg))
        elif opt == '-Q':
            options['query_strings'].append(process_arg(arg))
        elif opt == '--verify':
            options['verify'] = opt_verify(arg)
        elif opt == '--timeout':
            try:
                options['timeout'] = tuple(float(x) for x in arg.split(','))
            except ValueError as e:
                print('Invalid timeout %s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
            if len(options['timeout']) == 1:
                options['timeout'] = options['timeout'][0]
        elif opt == '--aio':
            options['aio'] = True
        elif opt == '--noaio':
            options['aio'] = False
        elif opt == '-j':
            options['print_json'] = True
        elif opt == '-p':
            options['print_python'] = True
        elif opt == '-J':
            if not have_jmespath:
                print('Install JMESPath for -J support: http://jmespath.org/',
                      file=sys.stderr)
                sys.exit(1)
            options['jmespath'] = arg
        elif opt == '--jwt':
            options['print_jwt'] = True
        elif opt == '--debug':
            try:
                options['debug'] = int(arg)
                if options['debug'] < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', arg, file=sys.stderr)
                sys.exit(1)
            if options['debug'] > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
        elif opt == '--dtime':
            options['dtime'] = True
        elif opt == '--version':
            print('pan-iot-security-python', __version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    for x in ['api-version', 'url',
              'access-key-id', 'access-key', 'customerid']:
        if x in options['config'] and options[x] is None:
            options[x] = options['config'][x]
    if 'verify' in options['config'] and options['verify'] is None:
        options['verify'] = opt_verify(options['config']['verify'])
    if options['verify'] is None:
        options['verify'] = True

    if options['json_requests']:
        obj = {}
        for r in options['json_requests']:
            try:
                x = json.loads(r)
            except ValueError as e:
                print('%s: %s' % (e, r), file=sys.stderr)
                sys.exit(1)
            obj.update(x)

        try:
            _ = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        options['json_request_obj'] = obj

    if options['query_strings']:
        obj = {}
        for r in options['query_strings']:
            try:
                x = json.loads(r)
            except ValueError as e:
                print('%s: %s' % (e, r), file=sys.stderr)
                sys.exit(1)
            obj.update(x)

        try:
            _ = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        options['query_string_obj'] = obj

    if options['debug'] > 2:
        x = copy.deepcopy(options)
        if x['access-key'] is not None:
            x['access-key'] = '*' * 6
        if x['config']['access-key'] is not None:
            x['config']['access-key'] = '*' * 6
        print(pprint.pformat(x), file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
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
    --api-version version    IoT API version (default %s)
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
'''
    print(usage % (os.path.basename(sys.argv[0]),
                   DEFAULT_API_VERSION), end='')


if __name__ == '__main__':
    main()
