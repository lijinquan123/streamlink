import platform
import threading
import time
from contextlib import suppress

import requests.adapters
import urllib3
from requests import Session

from streamlink.exceptions import HTTPStatusCodesError, PluginError
from streamlink.packages.requests_file import FileAdapter
from streamlink.plugin.api import useragents
from streamlink.utils import parse_json, parse_xml

try:
    # We tell urllib3 to disable warnings about unverified HTTPS requests,
    # because in some plugins we have to do unverified requests intentionally.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except AttributeError:
    pass


class _HTTPResponse(urllib3.response.HTTPResponse):
    def __init__(self, *args, **kwargs):
        # Always enforce content length validation!
        # This fixes a bug in requests which doesn't raise errors on HTTP responses where
        # the "Content-Length" header doesn't match the response's body length.
        # https://github.com/psf/requests/issues/4956#issuecomment-573325001
        #
        # Summary:
        # This bug is related to urllib3.response.HTTPResponse.stream() which calls urllib3.response.HTTPResponse.read() as
        # a wrapper for http.client.HTTPResponse.read(amt=...), where no http.client.IncompleteRead exception gets raised
        # due to "backwards compatiblity" of an old bug if a specific amount is attempted to be read on an incomplete response.
        #
        # urllib3.response.HTTPResponse.read() however has an additional check implemented via the enforce_content_length
        # parameter, but it doesn't check by default and requests doesn't set the parameter for enabling it either.
        #
        # Fix this by overriding urllib3.response.HTTPResponse's constructor and always setting enforce_content_length to True,
        # as there is no way to make requests set this parameter on its own.
        kwargs.update({"enforce_content_length": True})
        super().__init__(*args, **kwargs)


# override all urllib3.response.HTTPResponse references in requests.adapters.HTTPAdapter.send
urllib3.connectionpool.HTTPConnectionPool.ResponseCls = _HTTPResponse
requests.adapters.HTTPResponse = _HTTPResponse


def _parse_keyvalue_list(val):
    for keyvalue in val.split(";"):
        try:
            key, value = keyvalue.split("=", 1)
            yield key.strip(), value.strip()
        except ValueError:
            continue


class HTTPSession(Session):
    last_report_interval = 0

    def __init__(self):
        super().__init__()
        self.report_uri = None
        self.report_interval = 60
        self.stop_stream_playing = False
        self.error_http_status_codes = '403',
        self.headers['User-Agent'] = useragents.FIREFOX
        self.timeout = 20.0

        self.mount('file://', FileAdapter())

    # LJQ: BLOCK{
    # 添加上报接口和间隔
    @property
    def report_interval(self):
        return self._report_interval

    @report_interval.setter
    def report_interval(self, interval):
        self._report_interval = interval

    @property
    def report_uri(self):
        return self._report_uri

    @report_uri.setter
    def report_uri(self, uri):
        self._report_uri = uri

    def report_play_status(self, data: dict, protected=True):
        """
        上报当前播放状态
        """
        if protected:
            threading.Thread(target=self.report_play_status_protected, args=(data,), daemon=True).start()
        else:
            threading.Thread(target=self.report_play_status_only, args=(data,), daemon=True).start()

    def report_play_status_only(self, data: dict):
        with suppress(Exception):
            if self.report_uri and self.report_interval:
                self.request('post', self.report_uri, json=data, dont_report=True)

    def report_play_status_protected(self, data: dict):
        """
        上报当前播放状态
        """
        if time.time() - type(self).last_report_interval > 60 or not data.get('status'):
            type(self).last_report_interval = time.time()
            self.report_play_status_only(data)
            type(self).last_report_interval = time.time()

    # 添加错误码和停止流
    @property
    def stop_stream_playing(self):
        return self._stop_stream_playing

    @stop_stream_playing.setter
    def stop_stream_playing(self, stop_playing):
        self._stop_stream_playing = stop_playing

    @property
    def error_http_status_codes(self):
        return self._error_http_status_codes

    @error_http_status_codes.setter
    def error_http_status_codes(self, status_codes):
        """
        错误状态码解析错误范围
        """
        real_status_codes = []
        for status_code in status_codes:
            status_code = str(status_code).strip().upper()
            if not status_code:
                raise ValueError(f"--error-http-status-codes 不允许: {repr(status_code)}, 至少需要一个数字")
            if 'T' in status_code:
                status_codes_ = []
                num = 0
                for digit in status_code.split('T', 1):
                    digit = digit.strip() or None
                    if digit is not None:
                        digit = int(digit)
                        num += 1
                    status_codes_.append(digit)
                if num == 0:
                    raise ValueError(f"--error-http-status-codes 不允许: {repr(status_code)}, 至少需要一个数字")
                real_status_codes.append(status_codes_)
            else:
                real_status_codes.append(int(status_code))
        self._error_http_status_codes = real_status_codes

    # LJQ: BLOCK}
    @classmethod
    def determine_json_encoding(cls, sample):
        """
        Determine which Unicode encoding the JSON text sample is encoded with

        RFC4627 (http://www.ietf.org/rfc/rfc4627.txt) suggests that the encoding of JSON text can be determined
        by checking the pattern of NULL bytes in first 4 octets of the text.
        :param sample: a sample of at least 4 bytes of the JSON text
        :return: the most likely encoding of the JSON text
        """
        nulls_at = [i for i, j in enumerate(bytearray(sample[:4])) if j == 0]
        if nulls_at == [0, 1, 2]:
            return "UTF-32BE"
        elif nulls_at == [0, 2]:
            return "UTF-16BE"
        elif nulls_at == [1, 2, 3]:
            return "UTF-32LE"
        elif nulls_at == [1, 3]:
            return "UTF-16LE"
        else:
            return "UTF-8"

    @classmethod
    def json(cls, res, *args, **kwargs):
        """Parses JSON from a response."""
        # if an encoding is already set then use the provided encoding
        if res.encoding is None:
            res.encoding = cls.determine_json_encoding(res.content[:4])
        return parse_json(res.text, *args, **kwargs)

    @classmethod
    def xml(cls, res, *args, **kwargs):
        """Parses XML from a response."""
        return parse_xml(res.text, *args, **kwargs)

    def parse_cookies(self, cookies, **kwargs):
        """Parses a semi-colon delimited list of cookies.

        Example: foo=bar;baz=qux
        """
        for name, value in _parse_keyvalue_list(cookies):
            self.cookies.set(name, value, **kwargs)

    def parse_headers(self, headers):
        """Parses a semi-colon delimited list of headers.

        Example: foo=bar;baz=qux
        """
        for name, value in _parse_keyvalue_list(headers):
            self.headers[name] = value

    def parse_query_params(self, cookies, **kwargs):
        """Parses a semi-colon delimited list of query parameters.

        Example: foo=bar;baz=qux
        """
        for name, value in _parse_keyvalue_list(cookies):
            self.params[name] = value

    def resolve_url(self, url):
        """Resolves any redirects and returns the final URL."""
        return self.get(url, stream=True).url

    def is_error_status_codes(self, status_code):
        """
        错误状态码支持范围报错
        """
        for status_codes in self.error_http_status_codes:
            if isinstance(status_codes, int) and status_code == status_codes:
                return True
            elif isinstance(status_codes, list):
                start, end = status_codes
                if start is None:
                    if status_code < end:
                        return True
                elif end is None:
                    if status_code >= start:
                        return True
                elif start <= status_code < end:
                    return True
        return False

    def request(self, method, url, *args, **kwargs):
        acceptable_status = kwargs.pop("acceptable_status", [])
        exception = kwargs.pop("exception", PluginError)
        headers = kwargs.pop("headers", {})
        params = kwargs.pop("params", {})
        proxies = kwargs.pop("proxies", self.proxies)
        raise_for_status = kwargs.pop("raise_for_status", True)
        schema = kwargs.pop("schema", None)
        session = kwargs.pop("session", None)
        timeout = kwargs.pop("timeout", self.timeout)
        total_retries = kwargs.pop("retries", 0)
        retry_backoff = kwargs.pop("retry_backoff", 0.3)
        retry_max_backoff = kwargs.pop("retry_max_backoff", 10.0)
        dont_report = kwargs.pop("dont_report", False)
        retries = 0

        if session:
            headers.update(session.headers)
            params.update(session.params)

        while True:
            res = None
            length = None
            try:
                res = super().request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    timeout=timeout,
                    proxies=proxies,
                    *args,
                    **kwargs
                )
                length = int(res.headers.get("Content-Length", 0) or len(res.content))
                if platform.system().lower() == 'windows':
                    print(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {res.status_code} {res.request.method} '
                          f'{res.elapsed.total_seconds():.3f}s {length}bytes {res.url} {res.request.headers}')
                if raise_for_status and res.status_code not in acceptable_status:
                    res.raise_for_status()
                if self.is_error_status_codes(res.status_code):
                    raise HTTPStatusCodesError(res.status_code)
                msg = f'code: {res.status_code}, length: {length}'
                if not length and 200 <= res.status_code < 300 and method.lower() != 'options':
                    if exception:
                        raise exception(msg)
                    else:
                        raise HTTPStatusCodesError(msg)
                # LJQ: 上报播放正常状态
                if not dont_report:
                    self.report_play_status({'status': True, 'code': res.status_code, 'length': length})
                break
            except KeyboardInterrupt:
                raise
            except Exception as rerr:
                # LJQ: 错误状态码停止继续播放流或者不再重试请求
                if res is None:
                    # LJQ: 上报播放异常状态: 请求未响应
                    if not dont_report:
                        self.report_play_status({'status': None, 'code': None, 'length': length})
                else:
                    # LJQ: 上报播放异常状态: 状态码异常
                    if not dont_report:
                        self.report_play_status_protected({'status': False, 'code': res.status_code, 'length': length})
                    if self.is_error_status_codes(res.status_code):
                        if self.stop_stream_playing:
                            exception = HTTPStatusCodesError
                        err = exception(f"Unable to open URL: {url} ({res.status_code})")
                        err.err = rerr
                        raise err

                if retries >= total_retries:
                    mixed_exception = exception or HTTPStatusCodesError
                    err = mixed_exception(f"Unable to open URL: {url} ({rerr})")
                    err.err = rerr
                    raise err
                retries += 1
                # back off retrying, but only to a maximum sleep time
                delay = min(retry_max_backoff,
                            retry_backoff * (2 ** (retries - 1)))
                time.sleep(delay)

        if schema:
            res = schema.validate(res.text, name="response text", exception=PluginError)

        return res


__all__ = ["HTTPSession"]
