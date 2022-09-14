#!/usr/bin

# Colors
red='\e[1;31m'
default='\e[0m'
yellow='\e[0;33m'
orange='\e[38;5;166m'
green='\033[92m'

# Location
path=$(pwd)

# Check root 
if [ "$(id -u)" != "0" ] > /dev/null 2>&1; then
echo -e '\n$red[x] Este script necesita permisos root.' 1>&2
exit
fi

# Banner
clear
sleep 2
echo -e "$yellow  ____ ___      .__                 __         .__  .__     "
echo -e "$yellow |    |   \____ |__| ____   _______/  |______  |  | |  |    "
echo -e "$yellow |    |   /    \|  |/    \ /  ___/\   __\__  \ |  | |  |    "
echo -e "$yellow |    |  /   |  \  |   |  \\___ \   |  |  / __ \|  |_|  |__ "
echo -e "$yellow |______/|___|  /__|___|  /____  > |__| (____  /____/____/  "
echo -e "$yellow              \/        \/     \/            \/             "
echo -e "$yellow                                                            "
echo -e "$green                     Setup framework v1.3.2                  "

# Check if there is an internet connection
ping -c 1 google.com > /dev/null 2>&1
if [[ "$?" == 0 ]]; then
echo ""
echo -e "$green[✔][Internet Connection]............[ OK ]"
sleep 1.5
else
echo ""
echo -e "$red[!][Internet Connection].........[ NOT FOUND ]"
echo ""
exit
fi

if [ -f "/usr/share/applications/kithack.desktop" ]; then
rm /usr/share/applications/kithack.desktop
echo -e "[✔]/usr/share/applications/kithack.desktop"
sleep 0.2
fi

rm -rf $path
echo -e "[✔]$path"
sleep 0.2

echo -e "╔───────────────────────╗"
echo -e "|[✔] Uninstall complete.|"
echo -e "┖───────────────────────┙"
exit 



