import distro

INTEZER_APIKEY = ''
VT_APIKEY = ''
OTX_APIKEY = ''
MALSHARE_APIKEY = ''

IS_UBUNTU = distro.linux_distribution()[0].startswith('Ubuntu')
