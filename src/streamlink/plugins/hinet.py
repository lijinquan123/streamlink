"""
中华电信
https://www.hinet.net/tv/
"""
import base64
import json
import logging
import re
import time
from urllib.parse import urlparse

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.plugin.plugin import parse_url_params
from streamlink.stream import HLSStream
from streamlink.utils import update_scheme

logger = logging.getLogger(__name__)
RE_content = re.compile(r'"Content": "(.+?)"')
RE_channelId = re.compile(r'ChannelId: "(.+?)"')
RE_src = re.compile(r'<iframe.*?src="(?:index.php\?.*?VideoURL=)?(?P<url>.*?)"', re.S)
RE_src1 = re.compile(r'<source.*?src="(?P<url>.*?)"', re.S)


def get_url(html) -> str:
    try:
        url = RE_src.search(html).groupdict()['url']
    except (KeyError, Exception):
        url = RE_src1.search(html).groupdict()['url']
    return url


class Hinet(Plugin):
    arguments = PluginArguments(
        PluginArgument(
            "aec-key",
            default='VxzAfiseH0AbLShkQOPwdsssw5KyLeuv',
            sensitive=False,
            metavar="KEY",
            help="AES key"
        ),
    )
    _url_re = re.compile(r"(hinet\w*(?:variant)?://)?(.+(?:\.m3u8)?.*)")
    _tls_re = re.compile(r"(hinet(?P<TLS>\w*)(?:variant)?://).*")

    headers = {
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Referer": 'https://www.hinet.net/',
        "Origin": 'https://www.hinet.net',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/88.0.4324.182 Safari/537.36",
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

    @classmethod
    def can_handle_url(cls, url):
        m = cls._url_re.match(url)
        if m:
            url_path = urlparse(m.group(2)).path
            return m.group(1) is not None or url_path.endswith(".m3u8")

    def get_play_url(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        url = self.url
        if 'embed.4gtv.tv' in url:
            resp = self.session.http.request('get', url, timeout=self.timeout)
            try:
                content = RE_content.search(resp.text).group(1)
            except (IndexError, Exception):
                content = RE_channelId.search(resp.text).group(1)
            api = 'https://app.4gtv.tv/Data/HiNet/GetURL.ashx'
            params = {
                "ChannelNamecallback": "channelname",
                "Type": "LIVE",
                "Content": content,
                "HostURL": "https://www.hinet.net/",
                "_": int(time.time() * 1000)
            }
            resp = self.session.http.request('get', api, params=params, timeout=self.timeout)
            ciphertext = json.loads(resp.text[12:-1])['VideoURL']
            key = self.get_option("aec-key").encode('utf-8')
            iv = ciphertext[:16].encode('utf-8')
            plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(ciphertext[16:]))
            url = unpad(plaintext, AES.block_size, 'pkcs7').decode('utf-8')
        else:
            resp = self.session.http.request('get', url, timeout=self.timeout)
            url = get_url(resp.text)
            if '.html' in url:
                resp = self.session.http.request('get', url, timeout=self.timeout)
                url = get_url(resp.text)
            url = url.split('&')[0]
        return url

    def _get_streams(self):
        stream_url = self.get_play_url()
        logger.debug(f"Live stream url: {stream_url}")
        streams = HLSStream.parse_variant_playlist(self.session, stream_url)
        if not streams:
            return {"live": HLSStream(self.session, stream_url)}
        else:
            return streams


__plugin__ = Hinet
