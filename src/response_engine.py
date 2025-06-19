import os

# Function to block a suspicious IP using iptables
def block_ip(ip):
    print(f"🔒 Blocking IP: {ip}")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

# Function to alert the admin (console alert)
def alert_admin(ip):
    print(f"🚨 ALERT: Suspicious activity detected from {ip}")
import subprocess
import platform

def block_ip(ip_address):
    os_type = platform.system()
    
    print(f"🔒 Blocking IP: {ip_address}")

    if os_type == "Windows":
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in interface=any action=block remoteip={ip_address}', shell=True)
    elif os_type == "Linux":
        subprocess.run(f'sudo iptables -A INPUT -s {ip_address} -j DROP', shell=True)
    else:
        print("⚠️ Unsupported OS for IP blocking.")
