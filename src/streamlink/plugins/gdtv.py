"""
荔枝网

通过websocket获取加密node, 每20秒发送一次心跳
"""
import base64
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid

import websocket

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.stream import HLSStream

log = logging.getLogger(__name__)


class Gdtv(Plugin):
    arguments = PluginArguments(
        PluginArgument(
            "wss-api",
            sensitive=False,
            default="wss://tcdn-ws.itouchtv.cn:3800/connect",
            metavar="WSS_API",
            help="Wss api"
        )
    )
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/95.0.4638.69 Safari/537.36",
        "Referer": "https://www.gdtv.cn/",
        "Origin": "https://www.gdtv.cn",
        "Accept": "*/*",
    }
    _re_url = re.compile(r"https?://www.gdtv.cn/tvChannelDetail/(?P<channel_no>\d+)")

    def __init__(self, url):
        super().__init__(url)
        self.device_id = uuid.uuid1()
        self.channel_no = self._re_url.match(url).groupdict().get("channel_no")
        self.session.http.headers = self.headers
        self.ws = None

    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None

    def _get_streams(self):
        stream_url = self.get_livestream()
        log.debug("Live stream url: {}".format(stream_url))
        streams = HLSStream.parse_variant_playlist(self.session, stream_url, headers=self.headers)
        if not streams:
            return {"live": HLSStream(self.session, stream_url, headers=self.headers)}
        else:
            return streams

    def build_headers(self, url):
        timestamp = str(int(time.time() * 1000))
        secret = "dfkcY1c3sfuw0Cii9DWjOUO3iQy2hqlDxyvDXd1oVMxwYAJSgeB6phO8eW1dfuwX".encode('utf-8')
        message = f"GET\n{url}\n{timestamp}\n".encode('utf-8')
        signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest())
        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json",
            'X-iTouchTV-Ca-Timestamp': timestamp,
            'X-iTouchTV-Ca-Signature': signature,
            'X-iTouchTV-Ca-Key': '89541443007807288657755311869534',
            'X-iTouchTV-CLIENT': 'WEB_PC',
            'X-iTouchTV-DEVICE-ID': f'WEB_{self.device_id}',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/95.0.4638.69 Safari/537.36",
            "Referer": "https://www.gdtv.cn/",
            "Origin": "https://www.gdtv.cn",
        }

    def keep_connect(self, message: str):
        while True:
            time.sleep(20)
            self.ws.send(json.dumps({"route": "getwsparam", "message": message}, separators=(',', ': ')))

    def get_livestream(self):
        wss_api = self.get_option("wss-api")
        url = 'https://tcdn-api.itouchtv.cn/getParam'
        fake_node = self.session.http.request('get', url, headers=self.build_headers(url)).json()['node']
        self.ws = websocket.create_connection(wss_api, header=self.headers)
        self.ws.send(json.dumps({"route": "getwsparam", "message": fake_node}, separators=(',', ':')))
        threading.Thread(target=self.keep_connect, args=(fake_node,), daemon=True).start()
        node = base64.b64encode(json.loads(self.ws.recv())['wsnode'].encode()).decode()
        url = f'https://gdtv-api.gdtv.cn/api/tv/v2/tvChannel/{self.channel_no}?tvChannelPk={self.channel_no}&node={node}'
        self.session.http.request('options', url, headers=self.headers)
        resp = self.session.http.request('get', url, headers=self.build_headers(url))
        play_url = json.loads(resp.json()['playUrl'])['hd']
        return play_url


__plugin__ = Gdtv
