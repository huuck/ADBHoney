import json
import os

from ..config import CONFIG

class Output(object):
    def __init__(self):
        base = CONFIG.get('honeypot', 'log_dir')
        fn = CONFIG.get('output_json', 'log_file')
        self.fp = os.path.join(base, fn)

    def write(self, jsonlog):
        with open(self.fp, 'a') as f:
            json.dump(jsonlog, f)
            f.write('\n')
            f.flush()
