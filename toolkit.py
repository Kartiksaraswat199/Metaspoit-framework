#!/usr/bin/python3
# -*- coding: utf-8 -*-

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import os
import time
import sys
from sys import exit
from getch import pause
import main

location = os.getcwd()

#Tools Windows 
def Winpayloads():
	if not os.path.isdir('tools/Windows/Winpayloads'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/nccgroup/Winpayloads.git && cd Winpayloads && chmod +x setup.sh && bash setup.sh')
		print("\n{0}[✔] Done.{1}\nTool saved in {2}/tools/Windows/Winpayloads".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] do you want to run it?? (y/n)\n{1}framework >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')	
	else:
		print("\n{}[X] This tool already exists...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] do you want to run it? (y/n)\n{1}framework >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')

def sAINT():
	if not os.path.isdir('tools/Windows/sAINT'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && cd tools && cd Windows && git clone https://github.com/tiagorlampert/sAINT.git && cd sAINT && chmod +x configure.sh && bash configure.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/sAINT".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')

def BeeLogger():
	if not os.path.isdir('tools/Windows/BeeLogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/4w4k3/BeeLogger.git && cd BeeLogger && su && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/BeeLogger".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')

def FakeImageExploiter():
	if not os.path.isdir('tools/Windows/FakeImageExploiter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git && cd FakeImageExploiter && chmod +x *.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/FakeImageExploiter".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd FakeImageExploiter && bash FakeImageExploiter.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd FakeImageExploiter && bash FakeImageExploiter.sh')

def Koadic():
	if not os.path.isdir('tools/Windows/koadic'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/zerosum0x0/koadic.git && cd koadic && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/koadic".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd koadic && python koadic.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd koadic && python koadic.py')

def PhantomEvasion():
	if not os.path.isdir('tools/Windows/Phantom-Evasion'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/oddcod3/Phantom-Evasion.git && cd Phantom-Evasion && chmod +x phantom-evasion.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/Phantom-Evasion".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd Phantom-Evasion && python phantom-evasion.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd Phantom-Evasion && python phantom-evasion.py')

def Ps1encode():
	if not os.path.isdir('tools/Windows/ps1encode'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/CroweCybersecurity/ps1encode.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/ps1encode".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd ps1encode && ruby ps1encode.rb')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd ps1encode && ruby ps1encode.rb')

def DKMC():
	if not os.path.isdir('tools/Windows/DKMC'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/Mr-Un1k0d3r/DKMC.git && cd DKMC && mkdir output')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/DKMC".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')

def Cromos():
	if not os.path.isdir('tools/Windows/cromos'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/6IX7ine/cromos.git && chmod -R 777 cromos/ && cd cromos && python setup.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/cromos".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd cromos && python cromos.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd cromos && python cromos.py')

def EternalScanner():
	if not os.path.isdir('tools/Windows/eternal_scanner'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/peterpt/eternal_scanner.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/eternal_scanner".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd eternal_scanner && bash escan')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd eternal_scanner && bash escan')

def EternalblueDoublepulsarMetasploit():
	if not os.path.isdir('tools/Windows/Eternalblue-Doublepulsar-Metasploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git && cd Eternalblue-Doublepulsar-Metasploit && cp eternalblue_doublepulsar.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def MS17010EternalBlueWinXPWin10():
	if not os.path.isdir('tools/Windows/MS17-010-EternalBlue-WinXP-Win10'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10.git && cd MS17-010-EternalBlue-WinXP-Win10 && cp ms17_010_eternalblue_winXP-win10.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def WindowsExploits():
	if not os.path.isdir('tools/Windows/Exploits'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/WindowsExploits/Exploits.git')
		print("\n{0}[✔] Done.{1}\nExploits guardados en {2}/tools/Windows/Exploits".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()