# Installer 

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
echo -e '\n$red[x] This script needs root permissions.' 1>&2
exit
fi

# Banner 
clear
sleep 2
echo -e "$yellow  ___                 __         .__  .__                            "
echo -e "$yellow |   | ____   _______/  |______  |  | |  |   ___________             "    
echo -e "$yellow |   |/    \ /  ___/\   __\__  \ |  | |  | _/ __ \_  __ \            "    
echo -e "$yellow |   |   |  \___  \  |  |  / __ \|  |_|  |_\  ___/|  | \/            "    
echo -e "$yellow |___|___|  /____  > |__| (____  /____/____/\___  >__|   /\  /\  /\  "
echo -e "$yellow          \/     \/            \/               \/       \/  \/  \/  "
echo -e "                                                                            "
echo -e "$orange                                                        Setup v1.3.2 "
echo -e "                                                                            "
echo -e "$orange                                                         by:- Kartik "

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

# Check dependencies
echo -e $yellow
echo -n [*] checking dependencies...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""

# Check if xterm exists
which xterm > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo ""
echo -e "$green[✔][Xterm]..........................[ OK ]"
sleep 1.5
else
echo ""
echo -e "$red[x][Xterm].......................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Xterm...]"
sudo apt-get install -y xterm > /dev/null
fi

# Check if postgresql exists
which /etc/init.d/postgresql > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Postgresql].....................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Postgresql]..................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Postgresql...]"
xterm -T "INSTALLER POSTGRESQL" -geometry 100x30 -e "sudo apt-get install -y postgresql"
fi 

# Check if metasploit framework exists 
which msfconsole > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Metasploit Framework]...........[ OK ]"
sleep 1.5
else
echo -e "$red[x][Metasploit Framework]........[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Metasploit-Framework...]"
xterm -T "INSTALLER METASPLOIT FRAMEWORK" -geometry 100x30 -e "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall && sudo apt-get update && apt-get upgrade"
fi

# Check if ngrok exists
arch=`arch`
if [ -f "ngrok" ]; then
echo -e "$green[✔][Ngrok]..........................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Ngrok]........................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Downloading ngrok...]"
if [ "$arch" ==  "x86_64" ]; then
xterm -T "DOWNLOAD NGROK" -geometry 100x30 -e "wget https://bin.equinox.io/a/kpRGfBMYeTx/ngrok-2.2.8-linux-amd64.zip && unzip ngrok-2.2.8-linux-amd64.zip"
rm ngrok-2.2.8-linux-amd64.zip
else
xterm -T "DOWNLOAD NGROK" -geometry 100x30 -e "wget https://bin.equinox.io/a/4hREUYJSmzd/ngrok-2.2.8-linux-386.zip && unzip ngrok-2.2.8-linux-386.zip"
rm ngrok-2.2.8-linux-386.zip
fi
fi

# Configuring folders
echo -e $yellow
echo -n [*] configuring folders...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e $green

if [ -d output ]; then
echo -e "[✔]Ya existe $path/output"
sleep 0.2
else
mkdir output
echo -e "[✔]$path/output"
sleep 0.2
fi

if [ -d tools/Windows ]; then
echo -e "[✔]Ya existe $path/tools/Windows"
sleep 0.2
else
mkdir -p tools/Windows
echo -e "[✔]$path/tools/Windows"
sleep 0.2
fi

# Installing requirements
echo -e $yellow
echo -n [*] Installing python requirements...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e $green
pip3 install requests
pip3 install py-getch
apt-get install python3-tk
pip3 install pathlib
pip3 install zenipy
pip3 install pgrep
apt-get install libatk-adaptor libgail-common
sudo apt-get purge fcitx-module-dbus

# Shortcut for framework
echo -e $yellow
echo -n [*] Configure acess Setting...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo ""
echo -e "$green[!] You want to be able to run from anywhere in your terminal? (y/n)"
echo -e "$red"
echo -ne "framework>> $default"
read -r option
case "$option" in

y|Y)
lnk=$?
if [ "$lnk" ==  "0" ];then
run="cd $path && sudo python3 main.py"
touch /usr/local/bin/main
echo "#!/bin/bash" > /usr/local/bin/main
echo "$run" >> /usr/local/bin/main
chmod +x /usr/local/bin/main
sleep 2
echo -e $green
echo -e "╔──────────────────────────────────────────────────────────╗"
echo -e "|[✔] Installation complete. run the framework.|"
echo -e "┖──────────────────────────────────────────────────────────┙"
fi
;;

n|N)
sleep 2
echo -e $green
echo -e "╔──────────────────────────╗"
echo -e "|[✔] Installation complete.|"
echo -e "┖──────────────────────────┙"
;;
esac
exit