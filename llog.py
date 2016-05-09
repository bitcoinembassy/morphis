# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import logging
import logging.config
import traceback
import sys

logging_initialized = False;

def init():
    global logging_initialized
#    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    if (logging_initialized):
        return

#    print("Reading in logging.ini.")
    config_file = "logging.ini"
    if len(sys.argv) >= 3:
        if sys.argv[1] == "-l":
            config_file =  sys.argv[2]

    logging.config.fileConfig(config_file)
    logger = logging.getLogger(__name__)
#    logger.info("Logger initialized.")
    logging_initialized = True

def handle_exception(log, info):
    log.fatal("{} threw [{}]: {}".format(info, sys.exc_info()[0], str(sys.exc_info()[0])))
    traceback.print_tb(sys.exc_info()[2])

def printl(value):
    print({"value": value, "end": ''})

if not logging_initialized:
    init()
