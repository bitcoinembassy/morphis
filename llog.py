import logging
import logging.config
import traceback
import sys

logging_initialized = False;
contexts = {}

def init():
    global logging_initialized
#    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    if (logging_initialized):
        return

#    print("Reading in logging.ini.")
    logging.config.fileConfig("logging.ini")
    logger = logging.getLogger(__name__)
#    logger.info("Logger initialized.")
    logging_initialized = True

def handle_exception(log, info):
    log.fatal("{} threw [{}]: {}".format(info, sys.exc_info()[0], str(sys.exc_info()[0])))
    traceback.print_tb(sys.exc_info()[2])

def set_context(key, value):
    contexts[key] = value

def clear_context(key):
    del contexts[key]

class ContextFilter(logging.Filter):
    global contexts

    def filter(self, record):
        for key, value in contexts.items():
            record.__setattr__(key, value)

        return True

class ContextHandler(logging.StreamHandler):
    def __init__(self, *args, **kwargs):
        logging.StreamHandler.__init__(self, *args, **kwargs)

        self.addFilter(ContextFilter())

if not logging_initialized:
    init()
