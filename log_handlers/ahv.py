import logging
import sys

from salt.log.setup import LOGGING_TEMP_HANDLER


__virtualname__ = "ahv.log"


def __virtual__():
  return __virtualname__


class OptionalKeyFormatter(logging.Formatter):
  def __init__(self, opt_keys, opt_fmt, fmt=None, datefmt=None):
    self._opt_keys_set = set(opt_keys)
    self._opt_formatter = logging.Formatter(fmt=opt_fmt, datefmt=datefmt)
    logging.Formatter.__init__(self, fmt=opt_fmt, datefmt=datefmt)

  def format(self, record):
    if self._opt_keys_set.issubset(record.__dict__):
      ret = self._opt_formatter.format(record)
    else:
      ret = logging.Formatter.format(self, record)
    record.levelno = logging.NOTSET
    return ret


def setup_handlers():
  handler = logging.StreamHandler(sys.stdout)
  handler.setLevel(logging.INFO)
  fmt = LOGGING_TEMP_HANDLER.formatter._fmt
  fmt_atoms = fmt.split(" ")
  opt_fmt = "%s %s: %s" % (fmt_atoms[0], "%(instance_name)s", fmt_atoms[1])
  handler.setFormatter(
    OptionalKeyFormatter(["instance_name", ], opt_fmt, fmt=fmt))
  handler.addFilter(logging.Filter(name="ahv"))
  return handler
