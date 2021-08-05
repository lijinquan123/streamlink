# # LJQ: patch print for detail output, such as current file, current line, current time. BLOCK{
# class Patch(object):
#     @classmethod
#     def print(cls):
#         __builtins__['print'] = cls._print
#
#     @staticmethod
#     def _print(*args, sep=' ', end='\n', **kwargs):
#         import sys
#         import time
#         _frame = sys._getframe(1)
#         line = _frame.f_lineno
#         filename = _frame.f_code.co_filename
#         args = sep.join(str(arg) for arg in args)
#         sys.stdout.write(f'\033[3;32m{filename}:{line}  {time.strftime("%Y-%m-%d %H:%M:%S")}  {args}{end}\033[0m')
#
#
# Patch.print()
# # LJQ: BLOCK}


class StreamlinkError(Exception):
    """Any error caused by Streamlink will be caught
       with this exception."""


class PluginError(StreamlinkError):
    """Plugin related error."""


class FatalPluginError(PluginError):
    """
    Plugin related error that cannot be recovered from

    Plugin's should use this Exception when errors that can
    never be recovered from are encountered. For example, when
    a user's input is required an none can be given.
    """


class NoStreamsError(StreamlinkError):
    def __init__(self, url):
        self.url = url
        err = "No streams found on this URL: {0}".format(url)
        Exception.__init__(self, err)


class NoPluginError(PluginError):
    """No relevant plugin has been loaded."""


class StreamError(StreamlinkError):
    """Stream related error."""


# LJQ: 添加HTTP状态码403异常类
class HTTPStatusCode403Error(StreamlinkError):
    """Stream return 403 status code, raise 403 error"""


__all__ = ["StreamlinkError", "PluginError", "NoPluginError",
           "NoStreamsError", "StreamError", "HTTPStatusCode403Error", ]
