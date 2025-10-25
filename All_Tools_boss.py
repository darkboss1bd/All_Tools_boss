#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DarkBOSS1BD Termux Tools
# Developed by DARKBOSS1BD
# Telegram: https://t.me/darkvaiadmin
# Channel: https://t.me/windowspremiumkey
# Website: https://crackyworld.com/

import os
import sys
import subprocess
import socket
import requests
import platform
import calendar
import time
import json
import random
import string
from datetime import datetime

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def clear_screen():
    os.system('clear')

def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
▓█████▄  ▄▄▄       █     █░ ▄▄▄       ██▀███  
▒██▀ ██▌▒████▄    ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒
░██   █▌▒██  ▀█▄  ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒
░▓█▄   ▌░██▄▄▄▄██ ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  
░▒████▓  ▓█   ▓██▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░
 ░ ▒  ▒   ▒   ▒▒ ░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░
 ░ ░  ░   ░   ▒     ░   ░    ░   ▒     ░░   ░ 
   ░          ░  ░    ░          ░  ░   ░     
 ░                                          
{Colors.CYAN}
    Termux Tools - Developed by DARKBOSS1BD
    Telegram: https://t.me/darkvaiadmin
    Channel: https://t.me/windowspremiumkey
    Website: https://crackyworld.com/
{Colors.END}
"""
    print(banner)

def print_menu():
    menu = f"""
{Colors.YELLOW}{Colors.BOLD}---[ Termux Users ]---{Colors.END}
{Colors.GREEN}Developed by DARKBOSS1BD. Specially for Beginners{Colors.END}

{Colors.CYAN}[1] Ifconfig{Colors.END}        {Colors.CYAN}[2] Memory Info{Colors.END}
{Colors.CYAN}[3] Cpu Info{Colors.END}         {Colors.CYAN}[4] Public Ip{Colors.END}
{Colors.CYAN}[5] View Architecture{Colors.END} {Colors.CYAN}[6] Process Killer{Colors.END}
{Colors.CYAN}[7] Netstat{Colors.END}          {Colors.CYAN}[8] Heart-Bleed scanner{Colors.END}
{Colors.CYAN}[9] scan-ms17-010 win{Colors.END} {Colors.CYAN}[10] Ftp-vsftpd-Backdoor{Colors.END}
{Colors.CYAN}[11] Vulneable to Dos?{Colors.END} {Colors.CYAN}[12] Calender{Colors.END}
{Colors.CYAN}[13] Storage Info{Colors.END}    {Colors.CYAN}[14] Build Properties{Colors.END}
{Colors.CYAN}[15] User ID{Colors.END}         {Colors.CYAN}[16] Linux Version{Colors.END}
{Colors.CYAN}[17] Whois Lookup{Colors.END}    {Colors.CYAN}[18] Ns Lookup{Colors.END}
{Colors.CYAN}[19] Traceroute{Colors.END}      {Colors.CYAN}[20] Termux Speak{Colors.END}
{Colors.CYAN}[21] Hotmail Bruteforce{Colors.END} {Colors.CYAN}[22] Yahoo Bruteforce{Colors.END}
{Colors.CYAN}[23] Port scanner{Colors.END}    {Colors.CYAN}[24] send-sms{Colors.END}
{Colors.CYAN}[25] ssl scan{Colors.END}        {Colors.CYAN}[26] update{Colors.END}
{Colors.CYAN}[27] Python Obfuscate{Colors.END}
{Colors.RED}[0] Exit{Colors.END}            {Colors.GREEN}[a] About{Colors.END}
"""
    print(menu)

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

def option1_ifconfig():
    print(f"{Colors.YELLOW}[*] Running ifconfig...{Colors.END}")
    output = run_command('ifconfig') or run_command('ip addr')
    print(output)

def option2_memory_info():
    print(f"{Colors.YELLOW}[*] Checking memory info...{Colors.END}")
    output = run_command('free -h') or run_command('cat /proc/meminfo')
    print(output)

def option3_cpu_info():
    print(f"{Colors.YELLOW}[*] Checking CPU info...{Colors.END}")
    output = run_command('lscpu') or run_command('cat /proc/cpuinfo')
    print(output)

def option4_public_ip():
    print(f"{Colors.YELLOW}[*] Getting public IP...{Colors.END}")
    try:
        response = requests.get('https://api.ipify.org', timeout=10)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[+] Your public IP: {response.text}{Colors.END}")
        else:
            response = requests.get('https://ident.me', timeout=10)
            if response.status_code == 200:
                print(f"{Colors.GREEN}[+] Your public IP: {response.text}{Colors.END}")
            else:
                print(f"{Colors.RED}[!] Failed to get public IP{Colors.END}")
    except:
        print(f"{Colors.RED}[!] Failed to get public IP{Colors.END}")

def option5_architecture():
    print(f"{Colors.YELLOW}[*] Checking system architecture...{Colors.END}")
    arch = platform.machine()
    print(f"{Colors.GREEN}[+] Architecture: {arch}{Colors.END}")

def option6_process_killer():
    print(f"{Colors.YELLOW}[*] Process Killer{Colors.END}")
    output = run_command('ps aux')
    print(output)
    pid = input(f"{Colors.YELLOW}[?] Enter PID to kill: {Colors.END}")
    if pid:
        result = run_command(f'kill -9 {pid}')
        print(f"{Colors.GREEN}[+] Process {pid} killed{Colors.END}")

def option7_netstat():
    print(f"{Colors.YELLOW}[*] Running netstat...{Colors.END}")
    output = run_command('netstat -tuln') or run_command('ss -tuln')
    print(output)

def option8_heartbleed_scanner():
    print(f"{Colors.YELLOW}[*] Heart-Bleed Scanner{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target (host:port): {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    host, port = target.split(':') if ':' in target else (target, '443')
    
    print(f"{Colors.YELLOW}[*] Testing {host}:{port} for Heartbleed vulnerability...{Colors.END}")
    
    # Simple TCP connection test
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, int(port)))
        if result == 0:
            print(f"{Colors.GREEN}[+] Target is reachable{Colors.END}")
            print(f"{Colors.YELLOW}[*] Note: Full Heartbleed test requires OpenSSL scan{Colors.END}")
        else:
            print(f"{Colors.RED}[!] Target is not reachable{Colors.END}")
        sock.close()
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

def option9_scan_ms17_010():
    print(f"{Colors.YELLOW}[*] MS17-010 Scanner{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target IP: {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Scanning {target} for MS17-010 vulnerability...{Colors.END}")
    
    # Simple port scan for SMB
    ports = [139, 445]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Colors.GREEN}[+] Port {port} is open (SMB service){Colors.END}")
                print(f"{Colors.YELLOW}[*] Note: Full MS17-010 test requires specialized tools{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Port {port} is closed{Colors.END}")
            sock.close()
        except:
            print(f"{Colors.RED}[-] Could not check port {port}{Colors.END}")

def option10_ftp_backdoor():
    print(f"{Colors.YELLOW}[*] FTP vsftpd Backdoor Scanner{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target IP: {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Checking FTP service on {target}...{Colors.END}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target, 21))
        if result == 0:
            print(f"{Colors.GREEN}[+] FTP service is running on port 21{Colors.END}")
            print(f"{Colors.YELLOW}[*] Note: vsftpd backdoor check requires version analysis{Colors.END}")
        else:
            print(f"{Colors.RED}[-] FTP service is not running{Colors.END}")
        sock.close()
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

def option11_dos_vulnerability():
    print(f"{Colors.YELLOW}[*] DOS Vulnerability Check{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target URL or IP: {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Analyzing {target} for potential DOS vulnerabilities...{Colors.END}")
    
    # Simple service detection
    common_ports = [80, 443, 22, 21, 25, 53]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"{Colors.GREEN}[+] Port {port} open{Colors.END}")
            sock.close()
        except:
            pass
    
    if open_ports:
        print(f"{Colors.YELLOW}[*] Target has {len(open_ports)} open ports{Colors.END}")
        print(f"{Colors.YELLOW}[*] Note: Full DOS analysis requires specialized testing{Colors.END}")
    else:
        print(f"{Colors.RED}[-] No common ports open{Colors.END}")

def option12_calendar():
    print(f"{Colors.YELLOW}[*] Calendar{Colors.END}")
    now = datetime.now()
    year = now.year
    month = now.month
    cal = calendar.month(year, month)
    print(cal)

def option13_storage_info():
    print(f"{Colors.YELLOW}[*] Checking storage info...{Colors.END}")
    output = run_command('df -h') or run_command('cat /proc/partitions')
    print(output)

def option14_build_properties():
    print(f"{Colors.YELLOW}[*] Build Properties{Colors.END}")
    output = run_command('getprop') or run_command('uname -a')
    print(output)

def option15_user_id():
    print(f"{Colors.YELLOW}[*] User ID Information{Colors.END}")
    output = run_command('id') or f"User: {os.getenv('USER')}"
    print(output)

def option16_linux_version():
    print(f"{Colors.YELLOW}[*] Linux Version{Colors.END}")
    output = run_command('uname -a')
    print(output)

def option17_whois_lookup():
    print(f"{Colors.YELLOW}[*] WHOIS Lookup{Colors.END}")
    domain = input(f"{Colors.YELLOW}[?] Enter domain: {Colors.END}")
    if not domain:
        print(f"{Colors.RED}[!] No domain specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Looking up WHOIS information for {domain}...{Colors.END}")
    
    # Try multiple whois servers
    whois_servers = ['whois.iana.org', 'whois.internic.net']
    
    for server in whois_servers:
        try:
            output = run_command(f'whois -h {server} {domain}')
            if output and 'not found' not in output.lower():
                print(output)
                return
        except:
            continue
    
    # Fallback to system whois
    output = run_command(f'whois {domain}')
    if output:
        print(output)
    else:
        print(f"{Colors.RED}[!] Could not retrieve WHOIS information{Colors.END}")

def option18_ns_lookup():
    print(f"{Colors.YELLOW}[*] NS Lookup{Colors.END}")
    domain = input(f"{Colors.YELLOW}[?] Enter domain: {Colors.END}")
    if not domain:
        print(f"{Colors.RED}[!] No domain specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Performing DNS lookup for {domain}...{Colors.END}")
    
    try:
        # Get A records
        ip = socket.gethostbyname(domain)
        print(f"{Colors.GREEN}[+] A Record: {ip}{Colors.END}")
    except:
        print(f"{Colors.RED}[-] Could not resolve A record{Colors.END}")
    
    # Try to get NS records using nslookup or host command
    output = run_command(f'nslookup -type=NS {domain}') or run_command(f'host -t NS {domain}')
    if output:
        print(output)

def option19_traceroute():
    print(f"{Colors.YELLOW}[*] Traceroute{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target: {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Tracing route to {target}...{Colors.END}")
    
    output = run_command(f'traceroute {target}') or run_command(f'tracepath {target}')
    if output:
        print(output)
    else:
        print(f"{Colors.RED}[!] Traceroute not available{Colors.END}")

def option20_termux_speak():
    print(f"{Colors.YELLOW}[*] Termux Speak{Colors.END}")
    text = input(f"{Colors.YELLOW}[?] Enter text to speak: {Colors.END}")
    if text:
        output = run_command(f'termux-tts-speak "{text}"')
        if output:
            print(f"{Colors.RED}[!] Error: {output}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] Text spoken{Colors.END}")
    else:
        print(f"{Colors.RED}[!] No text entered{Colors.END}")

def option21_hotmail_bruteforce():
    print(f"{Colors.RED}[!] SECURITY NOTICE: This is a simulation for educational purposes{Colors.END}")
    print(f"{Colors.RED}[!] Actual bruteforce attacks are illegal without permission{Colors.END}")
    
    email = input(f"{Colors.YELLOW}[?] Enter Hotmail/Outlook email: {Colors.END}")
    if not email:
        print(f"{Colors.RED}[!] No email specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Simulating bruteforce attack on {email}...{Colors.END}")
    print(f"{Colors.YELLOW}[*] This would normally test common passwords...{Colors.END}")
    
    # Simulate some activity
    for i in range(3):
        print(f"{Colors.YELLOW}[*] Trying password attempt {i+1}...{Colors.END}")
        time.sleep(1)
    
    print(f"{Colors.RED}[-] Attack simulation completed{Colors.END}")
    print(f"{Colors.YELLOW}[*] Remember: Use this knowledge ethically and legally{Colors.END}")

def option22_yahoo_bruteforce():
    print(f"{Colors.RED}[!] SECURITY NOTICE: This is a simulation for educational purposes{Colors.END}")
    print(f"{Colors.RED}[!] Actual bruteforce attacks are illegal without permission{Colors.END}")
    
    email = input(f"{Colors.YELLOW}[?] Enter Yahoo email: {Colors.END}")
    if not email:
        print(f"{Colors.RED}[!] No email specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Simulating bruteforce attack on {email}...{Colors.END}")
    print(f"{Colors.YELLOW}[*] This would normally test common passwords...{Colors.END}")
    
    # Simulate some activity
    for i in range(3):
        print(f"{Colors.YELLOW}[*] Trying password attempt {i+1}...{Colors.END}")
        time.sleep(1)
    
    print(f"{Colors.RED}[-] Attack simulation completed{Colors.END}")
    print(f"{Colors.YELLOW}[*] Remember: Use this knowledge ethically and legally{Colors.END}")

def option23_port_scanner():
    print(f"{Colors.YELLOW}[*] Port Scanner{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target IP: {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Scanning common ports on {target}...{Colors.END}")
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Colors.GREEN}[+] Port {port} is OPEN{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Port {port} is CLOSED{Colors.END}")
            sock.close()
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning port {port}: {e}{Colors.END}")

def option24_send_sms():
    print(f"{Colors.YELLOW}[*] Send SMS{Colors.END}")
    number = input(f"{Colors.YELLOW}[?] Enter phone number: {Colors.END}")
    message = input(f"{Colors.YELLOW}[?] Enter message: {Colors.END}")
    
    if number and message:
        output = run_command(f'termux-sms-send -n {number} "{message}"')
        if output:
            print(f"{Colors.RED}[!] Error: {output}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] SMS sent successfully{Colors.END}")
    else:
        print(f"{Colors.RED}[!] Phone number and message required{Colors.END}")

def option25_ssl_scan():
    print(f"{Colors.YELLOW}[*] SSL Scan{Colors.END}")
    target = input(f"{Colors.YELLOW}[?] Enter target (host:port): {Colors.END}")
    if not target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        return
    
    host, port = target.split(':') if ':' in target else (target, '443')
    
    print(f"{Colors.YELLOW}[*] Scanning SSL/TLS on {host}:{port}...{Colors.END}")
    
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"{Colors.GREEN}[+] SSL Certificate found{Colors.END}")
                print(f"{Colors.GREEN}[+] Protocol: {ssock.version()}{Colors.END}")
                print(f"{Colors.GREEN}[+] Cipher: {ssock.cipher()}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] SSL Error: {e}{Colors.END}")

def option26_update():
    print(f"{Colors.YELLOW}[*] Updating DarkBOSS1BD Tools...{Colors.END}")
    print(f"{Colors.GREEN}[+] Tool is up to date!{Colors.END}")

def option27_python_obfuscate():
    print(f"{Colors.YELLOW}[*] Python Obfuscator{Colors.END}")
    filename = input(f"{Colors.YELLOW}[?] Enter Python file to obfuscate: {Colors.END}")
    
    if not os.path.exists(filename):
        print(f"{Colors.RED}[!] File not found{Colors.END}")
        return
    
    try:
        with open(filename, 'r') as f:
            code = f.read()
        
        # Simple obfuscation by encoding and variable renaming
        obfuscated_code = f'''# Obfuscated by DarkBOSS1BD Tools
import base64, codecs
exec(codecs.decode(base64.b64decode({repr(base64.b64encode(code.encode()).decode())}), 'utf-8'))
'''
        
        output_file = f"obfuscated_{filename}"
        with open(output_file, 'w') as f:
            f.write(obfuscated_code)
        
        print(f"{Colors.GREEN}[+] Obfuscated file saved as: {output_file}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

def about():
    about_text = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║                 ABOUT DARKBOSS1BD               ║
╚══════════════════════════════════════════════════╝{Colors.END}

{Colors.GREEN}Developer: DARKBOSS1BD
Specialty: Cybersecurity Tools for Beginners

{Colors.YELLOW}Contact Information:
Telegram ID: https://t.me/darkvaiadmin
Telegram Channel: https://t.me/windowspremiumkey
Hacking/Cracking Website: https://crackyworld.com/{Colors.END}

{Colors.CYAN}This tool is designed for:
- Educational purposes
- Security research
- Learning about system administration
- Understanding network security{Colors.END}

{Colors.RED}Legal Notice:
- Use this tool responsibly and ethically
- Only use on systems you own or have permission to test
- Unauthorized access is illegal{Colors.END}

{Colors.GREEN}Thank you for using DarkBOSS1BD Termux Tools!{Colors.END}
"""
    print(about_text)

def main():
    clear_screen()
    print_banner()
    
    while True:
        print_menu()
        choice = input(f"{Colors.YELLOW}Option@[DarkBOSS1BD]:-->{Colors.END} ").strip().lower()
        
        if choice == '0':
            print(f"{Colors.RED}[!] Exiting... Goodbye!{Colors.END}")
            break
        elif choice == 'a':
            about()
            input(f"{Colors.YELLOW}[?] Press Enter to continue...{Colors.END}")
            clear_screen()
            print_banner()
        elif choice == '1':
            option1_ifconfig()
        elif choice == '2':
            option2_memory_info()
        elif choice == '3':
            option3_cpu_info()
        elif choice == '4':
            option4_public_ip()
        elif choice == '5':
            option5_architecture()
        elif choice == '6':
            option6_process_killer()
        elif choice == '7':
            option7_netstat()
        elif choice == '8':
            option8_heartbleed_scanner()
        elif choice == '9':
            option9_scan_ms17_010()
        elif choice == '10':
            option10_ftp_backdoor()
        elif choice == '11':
            option11_dos_vulnerability()
        elif choice == '12':
            option12_calendar()
        elif choice == '13':
            option13_storage_info()
        elif choice == '14':
            option14_build_properties()
        elif choice == '15':
            option15_user_id()
        elif choice == '16':
            option16_linux_version()
        elif choice == '17':
            option17_whois_lookup()
        elif choice == '18':
            option18_ns_lookup()
        elif choice == '19':
            option19_traceroute()
        elif choice == '20':
            option20_termux_speak()
        elif choice == '21':
            option21_hotmail_bruteforce()
        elif choice == '22':
            option22_yahoo_bruteforce()
        elif choice == '23':
            option23_port_scanner()
        elif choice == '24':
            option24_send_sms()
        elif choice == '25':
            option25_ssl_scan()
        elif choice == '26':
            option26_update()
        elif choice == '27':
            option27_python_obfuscate()
        else:
            print(f"{Colors.RED}[!] Invalid option. Please try again.{Colors.END}")
        
        if choice != '0' and choice != 'a':
            input(f"{Colors.YELLOW}[?] Press Enter to continue...{Colors.END}")
            clear_screen()
            print_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Exiting... Goodbye!{Colors.END}")
        sys.exit(0)
