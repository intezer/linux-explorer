# update yara signatures from Neo23x0 github repo
#

wget -q https://github.com/Neo23x0/signature-base/archive/master.zip -O master.zip
rm -rf yara_rules/*
unzip -j master.zip signature-base-master/yara/* -d yara_rules
