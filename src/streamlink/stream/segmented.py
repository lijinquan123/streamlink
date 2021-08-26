import base64
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
import logging
import queue
from sys import version_info
from threading import Event, Thread
import time

from streamlink.buffers import RingBuffer
from streamlink.exceptions import HTTPStatusCode403Error
from streamlink.stream.stream import StreamIO

log = logging.getLogger(__name__)


class CompatThreadPoolExecutor(ThreadPoolExecutor):
    if version_info < (3, 9):
        def shutdown(self, wait=True, cancel_futures=False):
            with self._shutdown_lock:
                self._shutdown = True
                if cancel_futures:
                    # Drain all work items from the queue, and then cancel their
                    # associated futures.
                    while True:
                        try:
                            work_item = self._work_queue.get_nowait()
                        except queue.Empty:
                            break
                        if work_item is not None:
                            work_item.future.cancel()

                # Send a wake-up to prevent threads calling
                # _work_queue.get(block=True) from permanently blocking.
                self._work_queue.put(None)
            if wait:
                for t in self._threads:
                    t.join()


class SegmentedStreamWorker(Thread):
    """The general worker thread.

    This thread is responsible for queueing up segments in the
    writer thread.
    """

    def __init__(self, reader, **kwargs):
        self.closed = False
        self.reader = reader
        self.writer = reader.writer
        self.stream = reader.stream
        self.session = reader.stream.session

        self._wait = None

        Thread.__init__(self, name="Thread-{0}".format(self.__class__.__name__))
        self.daemon = True

    def close(self):
        """Shuts down the thread."""
        if not self.closed:
            log.debug("Closing worker thread")

        self.closed = True
        if self._wait:
            self._wait.set()

    def wait(self, time):
        """Pauses the thread for a specified time.

        Returns False if interrupted by another thread and True if the
        time runs out normally.
        """
        self._wait = Event()
        return not self._wait.wait(time)

    def iter_segments(self):
        """The iterator that generates segments for the worker thread.

        Should be overridden by the inheriting class.
        """
        return
        yield

    def run(self):
        for segment in self.iter_segments():
            if self.closed:
                break
            self.writer.put(segment)

        # End of stream, tells the writer to exit
        self.writer.put(None)
        self.close()


class SegmentedStreamWriter(Thread):
    """The writer thread.

    This thread is responsible for fetching segments, processing them
    and finally writing the data to the buffer.
    """
    upload403_map = {}

    def __init__(self, reader, size=20, retries=None, threads=None, timeout=None):
        self.closed = False
        self.reader = reader
        self.stream = reader.stream
        self.session = reader.stream.session

        if not retries:
            retries = self.session.options.get("stream-segment-attempts")

        if not threads:
            threads = self.session.options.get("stream-segment-threads")

        if not timeout:
            timeout = self.session.options.get("stream-segment-timeout")

        # LJQ: add stream-segment-upload-403-uri
        upload_uri = self.session.options.get("stream-segment-upload-403-uri")
        if upload_uri and not upload_uri.startswith("http"):
            upload_uri = str(base64.urlsafe_b64decode(upload_uri), encoding="utf-8")
        self.upload_uri = upload_uri

        self.retries = retries
        self.timeout = timeout
        self.executor = CompatThreadPoolExecutor(max_workers=threads)
        self.futures = queue.Queue(size)

        Thread.__init__(self, name="Thread-{0}".format(self.__class__.__name__))
        self.daemon = True

        # LJQ: 记录403次数，方便请求回掉接口 BLOCK{
        self.reset_403_count()

    def increase_403_count(self):
        self.raise403_count += 1
        # print(f'increase 403 count, raise403_count: {self.raise403_count}')

    def reset_403_count(self):
        self.raise403_count = 0
        # print(f'reset 403 count')
        # LJQ：BLOCK}

    def upload_403_error(self, url: str, headers: dict):
        # LJQ: 403异常时，上传异常请求
        # print('上传异常请求')
        if not self.upload_uri:
            return
        try:
            key = tuple(sorted(headers.items(), key=lambda x: x[0]))
            if key not in type(self).upload403_map or type(self).upload403_map[key] + 60 < time.time():
                resp = self.session.http.post(
                    self.upload_uri,
                    json={
                        'url': url,
                        'headers': dict(headers)
                    })
                type(self).upload403_map[key] = time.time()
                return resp.json()
        except Exception as e:
            log.error(e)

    def close(self):
        """Shuts down the thread."""
        if not self.closed:
            log.debug("Closing writer thread")

        self.closed = True
        self.reader.buffer.close()
        self.executor.shutdown(wait=True, cancel_futures=True)

    def put(self, segment):
        """Adds a segment to the download pool and write queue."""
        if self.closed:
            return

        if segment is not None:
            future = self.executor.submit(self.fetch, segment,
                                          retries=self.retries)
        else:
            future = None

        self.queue(self.futures, (segment, future))

    def queue(self, queue_, value):
        """Puts a value into a queue but aborts if this thread is closed."""
        while not self.closed:
            try:
                queue_.put(value, block=True, timeout=1)
                return
            except queue.Full:
                continue

    def fetch(self, segment):
        """Fetches a segment.

        Should be overridden by the inheriting class.
        """
        pass

    def write(self, segment, result):
        """Writes a segment to the buffer.

        Should be overridden by the inheriting class.
        """
        pass

    def run(self):
        while not self.closed:
            try:
                segment, future = self.futures.get(block=True, timeout=0.5)
            except queue.Empty:
                continue

            # End of stream
            if future is None:
                break

            while not self.closed:
                try:
                    result = future.result(timeout=0.5)
                except futures.TimeoutError:
                    continue
                except futures.CancelledError:
                    break

                # LJQ: 产生403异常，则放弃请求余下segment链接，重新拿取回掉数据 BLOCK{
                except HTTPStatusCode403Error as e:
                    self.futures.queue.clear()
                    self.increase_403_count()
                    # LJQ: 上传403请求头
                    self.upload_403_error(url=e.error.request.url, headers=e.error.request.headers)
                    # print('Result from raising 403 error, it will clear the queue and stop to request the rest HLS URL')
                    break
                else:
                    # request url normally then reset 403
                    if result and result.ok:
                        self.reset_403_count()
                # LJQ: BLOCK}

                if result is not None:
                    self.write(segment, result)

                break

        self.close()


class SegmentedStreamReader(StreamIO):
    __worker__ = SegmentedStreamWorker
    __writer__ = SegmentedStreamWriter

    def __init__(self, stream, timeout=None):
        StreamIO.__init__(self)
        self.session = stream.session
        self.stream = stream

        if not timeout:
            timeout = self.session.options.get("stream-timeout")

        self.timeout = timeout

    def open(self):
        buffer_size = self.session.get_option("ringbuffer-size")
        self.buffer = RingBuffer(buffer_size)
        self.writer = self.__writer__(self)
        self.worker = self.__worker__(self)

        self.writer.start()
        self.worker.start()

    def close(self):
        self.worker.close()
        self.writer.close()
        self.buffer.close()

    def read(self, size):
        if not self.buffer:
            return b""

        return self.buffer.read(size, block=self.writer.is_alive(),
                                timeout=self.timeout)
