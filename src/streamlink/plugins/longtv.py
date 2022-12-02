import logging
import re
from functools import partial

from streamlink.plugins.hls import HLSPlugin
from streamlink.stream import hls_playlist

log = logging.getLogger(__name__)


def longtv_decrypt(ciphertext):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    ciphertext = list(bytes.fromhex(ciphertext))
    keys = []
    sc = sum(ciphertext)
    while len(keys) < 16:
        b = (7 + sc * 23) % len(ciphertext)
        if b in keys:
            sc += 1
        else:
            keys.append(b)
            sc = b
    key = [0 for _ in range(16)]
    for k, i in sorted({k: i for i, k in enumerate(keys)}.items(), reverse=True):
        key[i] = ciphertext.pop(k)
    iv = [ciphertext.pop(0) for _ in range(16)]

    plaintext = AES.new(bytes(key), AES.MODE_CBC, bytes(iv)).decrypt(bytes(ciphertext))
    plaintext = unpad(plaintext, AES.block_size).decode('utf-8')
    return plaintext


class LongTVM3U8Parser(hls_playlist.M3U8Parser):
    def uri(self, uri):
        log.warning(f'{type(self).__class__.__name__}, uri: {uri}')
        if uri.isalnum():
            uri = longtv_decrypt(uri)
        return super().uri(uri)


class LongTV(HLSPlugin):
    _url_re = re.compile(r"(longtv\w*(?:variant)?://)?(.+(?:\.m3u8)?.*)")
    _tls_re = re.compile(r"(longtv(?P<TLS>\w*)(?:variant)?://).*")

    def __init__(self, url):
        hls_playlist.load = partial(hls_playlist.load, parser=LongTVM3U8Parser)
        super().__init__(url)


__plugin__ = LongTV
