import os
import logging
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
import queue

def get_call_logger(call_id):
    call_logger = logging.LoggerAdapter(logger, {'call_id': call_id})
    return call_logger

# Check MR_DEBUG env variable. Modes (shared with MindRoot server.py):
#   none            -> hard-disable ALL logging process-wide (production audio).
#   errors|error    -> ERROR+ only, GLOBALLY (logging.disable(WARNING)).
#                      This overrides any per-logger DEBUG/INFO levels set by
#                      libraries, which is the only reliable way to actually kill
#                      DEBUG spam. Real errors + stack traces still come through.
#   1|2|true|yes|debug -> full DEBUG logging.
#   (else / unset)  -> INFO.
_MR_DEBUG_RAW = os.environ.get('MR_DEBUG', '').lower()
MR_DEBUG = _MR_DEBUG_RAW in ('1', '2', 'true', 'yes', 'debug')

if MR_DEBUG:
    LOG_LEVEL = logging.DEBUG
elif _MR_DEBUG_RAW in ('errors', 'error', 'err'):
    LOG_LEVEL = logging.ERROR
else:
    LOG_LEVEL = logging.INFO

# Global floors. logging.disable(L) drops every record with severity <= L on
# ALL loggers regardless of their own level/handlers.
if _MR_DEBUG_RAW == 'none':
    logging.disable(logging.CRITICAL)        # everything off
elif _MR_DEBUG_RAW in ('errors', 'error', 'err'):
    logging.disable(logging.WARNING)         # only ERROR and CRITICAL survive

def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(LOG_LEVEL)
    #logger.setLevel(logging.ERROR)  # Only show errors and above

    # console handler
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    logger.addHandler(ch)

    # file handler
    fh = RotatingFileHandler('PySIP.log', maxBytes=1000000, backupCount=5)
    fh.setLevel(LOG_LEVEL)
    logger.addHandler(fh)

    # formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)

    return logger

def setup_async_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(LOG_LEVEL)


    # console handler
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)

    # file handler
    fh = RotatingFileHandler('PySIP.log')
    fh.setLevel(LOG_LEVEL)

    # formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)

    log_q = queue.SimpleQueue()
    queue_handler = QueueHandler(log_q)
    listener = QueueListener(log_q, ch, fh)

    logger.addHandler(queue_handler)

    return logger, ch, fh, listener

# If we want to use unblocking logger we have to un-comment this
# logger, console_handler, file_handler, listener = setup_async_logger()

logger = setup_logger()
console_handler = logger.handlers[0]
file_handler = logger.handlers[1]


