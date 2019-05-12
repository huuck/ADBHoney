import ConfigParser
import sys
import os

def read_config(cfg_file):
    config = ConfigParser.ConfigParser()
    config.readfp(open(cfg_file))
    return config

cfg_file = None
cfg_locations = ['/etc/adbhoney.cfg', 'adbhoney.cfg']
for l in cfg_locations:
    if os.path.exists(l):
        cfg_file = l
        break

if not cfg_file:
    print("Could not find config file!")
    sys.exit(1)

print("Loading config from {}".format(cfg_file))
CONFIG = read_config(cfg_file)
OUTPUT_PLUGINS = []
for section in CONFIG.sections():
    if section.startswith('output_'):
        enabled = CONFIG.get(section, 'enabled')
        if enabled == 'true':
            OUTPUT_PLUGINS.append(section)
