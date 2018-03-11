echo -e "\033[33m[*] fetching up-to-date yara signatures...\033[0m"
./update_signatures.sh

echo -e "\033[33m[*] starting Linux Expl0rer...\033[0m"
sudo python linux_explorer.py
