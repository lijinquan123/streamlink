"""
Tele TV

每次播放前自动登录账号
"""
import hashlib
import json
import logging
import random
import re
import time
from pathlib import Path

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.stream import HLSStream

logger = logging.getLogger(__name__)


class Tele(Plugin):
    arguments = PluginArguments(
        PluginArgument(
            "login-interval",
            default=60 * 60,
            sensitive=False,
            metavar="INTERVAL",
            help="login interval"
        ),
    )
    _re_url = re.compile(r"tele://.*?/live/(?P<username>\w+)/(?P<password>\w+)/(?P<channel_id>\w+)\.m3u8")

    def __init__(self, url):
        super().__init__(url)
        match = self._re_url.match(url).groupdict()
        self.username = match['username']
        self.password = match['password']
        self.channel_id = match['channel_id']
        self.domain = None
        self.tag = type(self).__name__
        self.dir = Path(__file__).parent.parent / 'data' / self.tag
        self.dir.mkdir(exist_ok=True, parents=True)
        self.file = self.dir / self.username

    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None

    def _get_streams(self):
        self.login()
        stream_url = f'{self.domain}/live/{self.username}/{self.password}/{self.channel_id}.m3u8'
        logger.debug(f"{self.tag} Live stream url: {stream_url}")
        streams = HLSStream.parse_variant_playlist(self.session, stream_url)
        if not streams:
            return {"live": HLSStream(self.session, stream_url)}
        else:
            return streams

    def login(self):
        interval = self.get_option("login-interval")
        try:
            last_login_time, self.domain = json.loads(self.file.read_text('utf-8'))
        except (FileNotFoundError, TypeError, Exception):
            last_login_time = 0
        cur_time = int(time.time())
        if last_login_time + interval > cur_time:
            logger.info(f'距上次登录时间太近, 此次不登录, interval: {interval}, last_login_time: {last_login_time}, cur_time: {cur_time}')
            return
        api = 'http://cpanel.magmatvs.com/SM/TeleTV/api/home.php?action=dns'
        headers = {
            "User-Agent": "IPTV Smarters Pro",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        key = 'K073f92926ef6072ac9b603bfffe9fd32'
        salt = 'NB!@#12ZKWd'
        username = ""
        random_num = random.randint(0, 8378600) + 10000
        av = '93.3'
        phone_name = 'OPPO PCRT00'
        android_version = '7.1.2 N'
        data = {
            "m": "gu",
            "k": key,
            "sc": hashlib.md5(f'{key}*{salt}-{username}-{random_num}-{av}-unknown-{phone_name}-{android_version}'.encode(
                'utf-8')).hexdigest(),
            "u": username,
            "pw": "no_password",
            "r": random_num,
            "av": av,
            "dt": "unknown",
            "d": phone_name,
            "do": android_version
        }
        resp = self.session.http.post(api, data=data, headers=headers)
        self.domain = resp.json()['su'].split(',')[0].strip(' /')
        logger.trace(f'{self.tag} domain: {self.domain}, {resp.status_code}, {resp.text}')
        self.file.write_text(json.dumps([int(time.time()), self.domain]), encoding='utf-8')
        api = f'{self.domain}/player_api.php'
        data = {
            'username': self.username,
            'password': self.password
        }
        resp = self.session.http.post(api, data=data)
        logger.info(f'{self.tag} login, {resp.status_code}, {resp.text}')


__plugin__ = Tele
