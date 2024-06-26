import hashlib
import logging
import os
import queue
import sys
import time
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from sys import version_info
from threading import Event, Thread

from streamlink.buffers import RingBuffer
from streamlink.exceptions import HTTPStatusCodesError
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


class SegmentedStreamStopper(Thread):
    """The stopper thread.

    This thread is responsible for stopping the stream
    if playback time greater than max playback duration
    """

    def __init__(self, reader):
        self.reader = reader
        self.stream = reader.stream
        self.session = reader.stream.session

        Thread.__init__(self, name="Thread-{0}".format(self.__class__.__name__))
        self.daemon = True
        self.stream_max_playback_duration = self.session.options.get("stream-max-playback-duration")
        if self.stream_max_playback_duration is None:
            self.stream_max_playback_duration = 0

    def run(self):
        log.debug(f'stream_max_playback_duration: {self.stream_max_playback_duration}')
        if self.stream_max_playback_duration > 0:
            sleep_time = self.stream_max_playback_duration - (time.time() - self.session.start_playback_time)
            log.warning(f'Stopped playback after {sleep_time} seconds!')
            time.sleep(sleep_time)
            self.close()

    def close(self):
        """Shuts down the thread."""
        self.reader.close()
        log.warning("Closing stopper thread")
        sys.exit(1)


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

        self.retries = retries
        self.timeout = timeout
        self.executor = CompatThreadPoolExecutor(max_workers=threads)
        self.futures = queue.Queue(size)

        Thread.__init__(self, name="Thread-{0}".format(self.__class__.__name__))
        self.daemon = True

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
                except HTTPStatusCodesError as e:
                    log.error(f"Failed to open segment: {e}")
                    # stop all waiting segments to request
                    self.futures.queue.clear()
                    # stop reloading playlist
                    self.reader.worker.closed = True
                    break
                if result is not None:
                    self.write(segment, result)

                break

        self.close()

    @staticmethod
    def has_drm_decrypted(encrypt_file: str, decrypt_file: str):
        # AES-CBC模式必须使用填充,因此加密后的文件长度比解密的文件长度大.
        # AES-CTR模式不使用填充,因此加密后的文件长度和解密的文件长度相同.
        # 因此通过`截取文件后10M并比较MD5值`的方式来判断是否解密成功
        encrypt_size = os.path.getsize(encrypt_file)
        decrypt_size = os.path.getsize(decrypt_file)
        if encrypt_size != decrypt_size:
            return True
        read_size = 10 * 1024 * 1024
        with open(encrypt_file, mode='rb') as f:
            f.seek(max(0, encrypt_size - read_size))
            encrypt_md5 = hashlib.md5(f.read()).hexdigest()
        with open(decrypt_file, mode='rb') as f:
            f.seek(max(0, decrypt_size - read_size))
            decrypt_md5 = hashlib.md5(f.read()).hexdigest()
        return encrypt_md5 != decrypt_md5


class SegmentedStreamReader(StreamIO):
    __worker__ = SegmentedStreamWorker
    __writer__ = SegmentedStreamWriter
    __stopper__ = SegmentedStreamStopper

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
        self.stopper = self.__stopper__(self)

        self.writer.start()
        self.worker.start()
        self.stopper.start()

    def close(self):
        self.worker.close()
        self.writer.close()
        self.buffer.close()

    def read(self, size):
        if not self.buffer:
            return b""

        return self.buffer.read(size, block=self.writer.is_alive(),
                                timeout=self.timeout)
