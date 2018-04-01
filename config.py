# config.py

import sys
import platform

reload(sys) # fix encoding issues
sys.setdefaultencoding('utf8')

VT_APIKEY       = ''
OTX_APIKEY      = ''
MALSHARE_APIKEY = ''

IS_UBUNTU = platform.linux_distribution()[0].startswith('Ubuntu')
