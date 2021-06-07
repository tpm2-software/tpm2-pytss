import datetime
import logging
import os
import re
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)


def makeRecord(
    self, name, level, fn, lno, msg, args, exc_info, func=None, extra=None, sinfo=None,
):
    """
    A factory method which can be overridden in subclasses to create
    specialized LogRecords.
    """
    rv = logging.LogRecord(name, level, fn, lno, msg, args, exc_info, func, sinfo)
    if extra is not None:
        for key in extra:
            rv.__dict__[key] = extra[key]
    return rv


# monkey-patch Logger.makeRecord to be able to overwrite pathname, lineno and func
logging.Logger.makeRecord = makeRecord


tss_modules = [
    "fapi",
    "fapijson",
    "esys",
    "esys_crypto",
    "sys",
    "marshal",
    "tcti",
    "log",
    "test",
]

tss_loggers = {module: logging.getLogger(f"TSS.{module}") for module in tss_modules}


class RawLogRecord:  # TODO doc
    def __init__(self, text):
        self.timestamp = datetime.datetime.now()
        self._text = text

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        self.timestamp = datetime.datetime.now()
        self._text = value

    @property
    def is_expired(self):
        return datetime.datetime.now() - self.timestamp > datetime.timedelta(seconds=1)


class ConsumeTssLogs(threading.Thread):
    def __init__(self):
        super().__init__()
        self.log_records: List[RawLogRecord] = []
        self.pipe_r, self.pipe_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

        # Redirect TSS logging to pipe
        os.environ["TSS2_LOGFILE"] = f"/dev/fd/{self.pipe_w}"

        # Crank up TSS logging and filter through the python log levels
        os.environ["TSS2_LOG"] = "all+trace"

    def run(self):
        """Read TSS logging stream from pipe and process."""
        main_dead_counter = 0

        while True:
            data = b""
            while True:
                try:
                    data += os.read(self.pipe_r, 1024)
                except BlockingIOError:
                    # pipe is empty
                    break

            self.process(data)

            # end after main thread is dies
            if not threading.main_thread().is_alive():
                break

        self.process(flush=True)
        os.close(self.pipe_r)
        os.close(self.pipe_w)

    def process(self, data: Optional[bytes] = None, flush: bool = True):
        """Parse raw TSS logging stream and feed log records into the python logging system. Caches last record."""
        if not data:
            if not flush:
                return
            data = b""

        for line in data.decode().splitlines():
            if re.match(r"^.+?:.+?:.+?:\d+?:.+?\(\) .+", line):
                # line starts new log record
                self.log_records.append(RawLogRecord(line))
            elif self.log_records:
                # line belongs to previous log record
                self.log_records[-1].text += f"\n{line}"
            else:
                logger.error(f"Cannot parse TSS stderr:\n{line}")
                continue

        # process everything except last log_record (because more there might be more data)
        for log_record in self.log_records[:-1]:
            self.publish(log_record)

        # cache last record (if not expired)
        if self.log_records:
            last_log_record = self.log_records[-1]
            if last_log_record.is_expired:
                self.publish(last_log_record)
                self.log_records = []
            else:
                self.log_records = [last_log_record]

    @staticmethod
    def publish(log_record: RawLogRecord):
        """Parse and public a single log record."""
        # parse stderr
        level, module, filename, lineno, func, message = re.split(
            ":| ", log_record.text.strip(), maxsplit=5
        )

        # map TSS2 logging levels to python levels
        level = {
            "error": "error",
            "warning": "warning",
            "info": "info",
            "debug": "debug",
            "trace": "debug",
        }[level.lower()]

        # choose logger and log level
        log_function = getattr(tss_loggers[module], level)

        # pass message to logger
        log_function(
            f"{message}",
            extra={"pathname": filename, "lineno": int(lineno), "func": func},
        )


# Consume TSS logging stream
ConsumeTssLogs().start()
