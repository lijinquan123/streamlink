"""
牛视网
https://www.chaojidianshi.net/
"""
import base64
import logging
import re
from contextlib import suppress
from urllib.parse import urlsplit, urlunsplit

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.stream import HLSStream

logger = logging.getLogger(__name__)


class NSW(Plugin):
    arguments = PluginArguments(
        PluginArgument(
            "aec-key",
            default='12345678988baixh',
            sensitive=False,
            metavar="KEY",
            help="AES key"
        ),
        PluginArgument(
            "aec-iv",
            default='TTDNwyJtHesysVPN',
            sensitive=False,
            metavar="IV",
            help="AES iv"
        ),
        PluginArgument(
            "select",
            default=0,
            metavar="NUMBER",
            help="select the source what you want"
        ),
    )
    _re_url = re.compile(r"https?://www\.chaojidianshi\.net/.+")
    headers = {
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/113.0.0.0 Safari/537.36",
        "Origin": "https://www.chaojidianshi.net",
        "Referer": "https://www.chaojidianshi.net/",
        "Accept-Language": "zh-CN,zh;q=0.9"
    }

    def __init__(self, url):
        super().__init__(url)
        self.timeout = 10
        self.session.http.headers = self.headers

    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None

    def select_sources(self, sources: list) -> list:
        select = int(self.get_option("select"))
        try:
            if select != 0:
                select -= select > 0
                sources = [sources[select]]
        except Exception as e:
            logger.error(f'sources: {len(sources)}, select: {select}, error: {e}')
        return sources

    @staticmethod
    def url_adapter(url: str, stems: str, target: str = '.m3u8'):
        if isinstance(stems, str):
            stems = [stems]
        parse = list(urlsplit(url))
        for stem in stems:
            if parse[2].endswith(stem):
                parse[2] = f'{parse[2][:-4]}{target}'
                break
        url = urlunsplit(parse)
        return url

    def _get_streams(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from lxml import html
        key = self.get_option("aec-key").encode('utf-8')
        iv = self.get_option("aec-iv").encode('utf-8')
        resp = self.session.http.request('get', self.url, timeout=self.timeout)
        root = html.fromstring(resp.text)
        url = None
        sources = self.select_sources(root.xpath('//div[@class="ad"]/a'))
        for a in sources:
            with suppress(Exception):
                u = a.xpath('@href')[0]
                if not u.startswith('http'):
                    u = f'https://www.chaojidianshi.net{u}'
                resp = self.session.http.request('get', u, timeout=self.timeout)
                ciphertext = html.fromstring(resp.text).xpath('//*[@class="show_player_txt"]/text()')[0]
                plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(ciphertext))
                plaintext = unpad(plaintext, AES.block_size, 'pkcs7').decode('utf-8')
                url = plaintext[4:]
                if url:
                    break
        if not url:
            raise ValueError(f'未解析到播放链接: {url}')
        stream_url = self.url_adapter(url, '.flv')
        logger.debug(f"Live stream url: {stream_url}")
        streams = HLSStream.parse_variant_playlist(self.session, stream_url)
        if not streams:
            return {"live": HLSStream(self.session, stream_url)}
        else:
            return streams


__plugin__ = NSW
