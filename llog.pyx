import logging
import logging.config

logging_initialized = False;

def init():
    global logging_initialized
#    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    if (not logging_initialized):
#        print("Reading in logging.ini.")
        logging.config.fileConfig("logging.ini")
        logger = logging.getLogger(__name__)
#        logger.info("Logger initialized.")
