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

import logging
import requests
import ssl
import sys
import time

from . import (mixin, ApiError, ArgsError,
               DEBUG1, DEBUG2, DEBUG3, __version__)


BASE_PATH = '/pub/v4.0'


class IotApi(mixin.Mixin):
    def __init__(self, *,
                 api_version=None,
                 url=None,
                 access_key_id=None,
                 access_key=None,
                 customerid=None,
                 verify=None,
                 timeout=None):
        self._log = logging.getLogger(__name__).log
        self._log(DEBUG2, 'pan-iot-security-python: %s, IotApi: %s',
                  __version__, api_version)
        self._log(DEBUG2, 'Python version: %s', sys.version)
        self._log(DEBUG2, 'ssl: %s', ssl.OPENSSL_VERSION)
        self._log(DEBUG2, 'requests: %s', requests.__version__)

        self.api_version = api_version
        if customerid is None:
            raise ArgsError('customerid required')
        self.customerid = customerid
        if url is None:
            self.url = 'https://%s.iot.paloaltonetworks.com' % customerid
        else:
            self.url = url
        auth = self._auth(access_key_id, access_key)
        self.session = self._session(auth=auth,
                                     verify=verify,
                                     timeout=timeout)

    def _request_retry(self, retry, delay, func, **kwargs):
        while True:
            resp = func(**kwargs)
            if retry and resp.status_code == 429:
                self._log(DEBUG2, 'status code 429, sleep %.2fs', delay)
                time.sleep(delay)
            else:
                break

        return resp

    def device(self, *,
               stime=None,
               detail=False,
               offset=None,
               pagelength=None,
               query_string=None,
               retry=False):
        path = BASE_PATH + '/device/list'
        url = self.url + path

        params = {'customerid': self.customerid}
        if stime is not None:
            params['stime'] = stime
        if detail is True:
            params['detail'] = 'true'
        if offset is not None:
            params['offset'] = offset
        if pagelength is not None:
            params['pagelength'] = pagelength
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        # rate limit: 60 requests per minute
        seconds = 60/60
        resp = self._request_retry(retry, seconds,
                                   self.session.get, **kwargs)

        return resp

    def _get_all(self, func, key, **kwargs):
        offset = 0
        pagelength = 1000

        while True:
            resp = func(offset=offset,
                        pagelength=pagelength,
                        retry=True,
                        **kwargs)
            if resp.status_code == 200:
                obj = resp.json()
                try:
                    length = len(obj[key])
                    for x in obj[key]:
                        yield x
                except KeyError as e:
                    raise ApiError('Malformed response, missing key %s' % e)
            else:
                resp.raise_for_status()

            self._log(DEBUG2, 'length %d', length)
            if length < pagelength:
                self._log(DEBUG1, 'total %d', offset+length)
                return
            offset += length

    def devices_all(self, *,
                    stime=None,
                    detail=False,
                    query_string=None):
        kwargs = {
            'stime': stime,
            'detail': detail,
            'query_string': query_string,
        }

        for x in self._get_all(func=self.device,
                               key='devices',
                               **kwargs):
            yield x

    def device_details(self, *,
                       deviceid=None,
                       ip=None,
                       query_string=None,
                       retry=False):
        if deviceid is None and ip is None:
            raise ArgsError('deviceid or ip required')
        if deviceid is not None and ip is not None:
            raise ArgsError(
                'deviceid and ip cannot be used at the same time')

        kwargs = {
            'params': {'customerid': self.customerid},
        }

        if deviceid is not None:
            path = BASE_PATH + '/device'
            url = self.url + path
            kwargs['params']['deviceid'] = deviceid
        if ip is not None:
            path = BASE_PATH + '/device/ip'
            url = self.url + path
            kwargs['params']['ip'] = ip
        if query_string is not None:
            kwargs['params'].update(query_string)

        kwargs['url'] = url

        # rate limit: 600 requests per minute
        seconds = 60/600
        resp = self._request_retry(retry, seconds,
                                   self.session.get, **kwargs)

        return resp

    def vulnerability(self, *,
                      stime=None,
                      deviceid=None,
                      offset=None,
                      pagelength=None,
                      query_string=None,
                      retry=False):
        path = BASE_PATH + '/vulnerability/list'
        url = self.url + path

        params = {'customerid': self.customerid}
        if stime is not None:
            params['stime'] = stime
        if deviceid is not None:
            params['deviceid'] = deviceid
            params['groupby'] = 'vulnerability'
        else:
            params['groupby'] = 'device'
        if offset is not None:
            params['offset'] = offset
        if pagelength is not None:
            params['pagelength'] = pagelength
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.get, **kwargs)

        return resp

    def vulnerabilities_all(self, *,
                            stime=None,
                            query_string=None):
        kwargs = {
            'stime': stime,
            'query_string': query_string,
        }

        for x in self._get_all(func=self.vulnerability,
                               key='items',
                               **kwargs):
            yield x

    def alert(self, *,
              offset=None,
              pagelength=None,
              query_string=None,
              retry=False):
        path = BASE_PATH + '/alert/list'
        url = self.url + path

        params = {'customerid': self.customerid}
        if offset is not None:
            params['offset'] = offset
        if pagelength is not None:
            params['pagelength'] = pagelength
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.get, **kwargs)

        return resp

    def alerts_all(self, *,
                   query_string=None):
        kwargs = {
            'query_string': query_string,
        }

        for x in self._get_all(func=self.alert,
                               key='items',
                               **kwargs):
            yield x

    def tag(self, *,
            query_string=None,
            retry=False):
        path = BASE_PATH + '/tag/list'
        url = self.url + path

        params = {
            'customerid': self.customerid,
            'source': 'tenant',
        }

        kwargs = {
            'url': url,
            'params': params,
        }

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.get, **kwargs)

        return resp

    def device_update(self, *,
                      json=None,
                      query_string=None,
                      retry=False):
        path = BASE_PATH + '/device/update'
        url = self.url + path

        params = {
            'customerid': self.customerid,
        }
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }
        if json is not None:
            if isinstance(json, (bytes, str, bytearray)):
                kwargs['data'] = json
                kwargs['headers'] = {'content-type': 'application/json'}
            else:
                kwargs['json'] = json

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.put, **kwargs)

        return resp

    def vuln_update(self, *,
                    json=None,
                    query_string=None,
                    retry=False):
        path = BASE_PATH + '/vulnerability/update'
        url = self.url + path

        params = {
            'customerid': self.customerid,
        }
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }
        if json is not None:
            if isinstance(json, (bytes, str, bytearray)):
                kwargs['data'] = json
                kwargs['headers'] = {'content-type': 'application/json'}
            else:
                kwargs['json'] = json

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.put, **kwargs)

        return resp

    def alert_update(self, *,
                     id=None,
                     json=None,
                     query_string=None,
                     retry=False):
        path = BASE_PATH + '/alert/update'
        url = self.url + path

        params = {
            'customerid': self.customerid,
        }
        if id is not None:
            params['id'] = id
        if query_string is not None:
            params.update(query_string)

        kwargs = {
            'url': url,
            'params': params,
        }
        if json is not None:
            if isinstance(json, (bytes, str, bytearray)):
                kwargs['data'] = json
                kwargs['headers'] = {'content-type': 'application/json'}
            else:
                kwargs['json'] = json

        # rate limit: 180 requests per minute
        seconds = 60/180
        resp = self._request_retry(retry, seconds,
                                   self.session.put, **kwargs)

        return resp
