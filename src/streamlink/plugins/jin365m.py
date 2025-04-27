import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from streamlink import StreamError
from streamlink.plugin import Plugin
from streamlink.plugin.plugin import parse_url_params
from streamlink.stream import HLSStream
from streamlink.utils import update_scheme


class Jin365m(Plugin):
    _url_re = re.compile(r"(jin365m\w*(?:variant)?://)?(.+(?:\.m3u8)?.*)")
    _tls_re = re.compile(r"(jin365m(?P<TLS>\w*)(?:variant)?://).*")
    headers = {
        "User-Agent": "Mozila/5.0 (Android 4.4; Mobile;)",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Icy-MetaData": "1"
    }

    def __init__(self, url):
        super().__init__(url)
        self.timeout = 10
        self.session.http.headers = self.headers
        url, params = parse_url_params(self.url)
        urlnoproto = self._url_re.match(url).group(2)
        scheme = "http"
        tls_match = self._tls_re.match(url)
        if tls_match and bool(tls_match.groupdict()['TLS']):
            scheme = f'{scheme}s'
        self.url = update_scheme(f'{scheme}://', urlnoproto)
        tmp_dir = Path(self.session.options.get("drm-temp-dir") or '/tmp/drm')
        self.login_file = tmp_dir / 'jin365m.json'

    @classmethod
    def can_handle_url(cls, url):
        return url[:7] == 'jin365m'

    @staticmethod
    def url_adapter(url: str, stems: (str, list), target: str = '.m3u8'):
        if isinstance(stems, str):
            stems = [stems]
        parse = list(urlsplit(url))
        for stem in stems:
            if parse[2].endswith(stem):
                parse[2] = f'{parse[2][:-4]}{target}'
                break
        url = urlunsplit(parse)
        return url

    def login(self):
        api = 'http://jins365m.webredirect.org/live/zb.php'
        data = {
            'name': 'com.jrys.app',
            'QQ': '3119374819'
        }
        resp = self.session.http.request('post', api, headers=self.headers, data=data, timeout=self.timeout)
        code = resp.status_code
        self.login_file.write_text(f'{code}_{int(time.time())}', encoding='utf-8')
        if not resp.ok:
            # 登录失败,上传登录状态码
            length = int(resp.headers.get("Content-Length", 0) or len(resp.content))
            self.session.http.report_play_status_protected({'status': False, 'code': code + 3000, 'length': length})

    def _get_streams(self):
        resp = self.session.http.request('get', self.url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
        next_resp = resp.next
        if next_resp is None:
            # 如果没有跳转地址,则需要登录
            try:
                code, login_time = self.login_file.read_text('utf-8').split('_')
            except (FileNotFoundError, Exception):
                login_time = 0
            if time.time() - int(login_time) > 7200:
                # 距上次登录时间已超过7200s则登录
                self.login()
            else:
                # 未知错误,只记录不处理
                length = int(resp.headers.get("Content-Length", 0) or len(resp.content))
                self.session.http.report_play_status_protected({'status': False, 'code': resp.status_code + 1000, 'length': length})
            raise StreamError()
        stream_url = self.url_adapter(resp.next.url, ['.flv'])
        streams = HLSStream.parse_variant_playlist(self.session, stream_url)
        if not streams:
            return {"live": HLSStream(self.session, stream_url)}
        else:
            return streams


__plugin__ = Jin365m
