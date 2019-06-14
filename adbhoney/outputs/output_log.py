import logging
import json
import os

from ..config import CONFIG

levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'error': logging.ERROR
        }

class Output(object):
    def __init__(self):
        self.__name__ = "output_log"
        BASE = CONFIG.get('honeypot', 'log_dir')
        FILENAME = CONFIG.get('output_log', 'log_file')
        LOG_LEVEL = levels[CONFIG.get('output_log', 'log_level').lower()]
        FORMAT = '%(asctime)s - %(thread)s - %(name)s - %(levelname)s - %(message)s'
        FORMATTER = logging.Formatter(FORMAT)
        logging.basicConfig(format=FORMAT)
        self.log_file = os.path.join(BASE, FILENAME)
        self.logger = logging.getLogger('ADBHoneypot')
        self.logger.setLevel(LOG_LEVEL)

        if not os.path.exists(BASE):
            os.makedirs(BASE)
        if not os.path.exists(self.log_file):
            open(self.log_file, 'w').close()

        FILE_HANDLER = logging.FileHandler(self.log_file)
        FILE_HANDLER.setFormatter(FORMATTER)
        FILE_HANDLER.setLevel(LOG_LEVEL)
        self.logger.addHandler(FILE_HANDLER)

    def write(self, message, level=logging.INFO):
        if level is logging.DEBUG:
            self.logger.debug(message)
        elif level is logging.INFO:
            self.logger.info(message)
        elif level is logging.ERROR:
            self.logger.error(message)
