from scapy.all import *

# Print all available network interfaces
print("Available Network Interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")
    
# Also show IP addresses
print("\nInterfaces with IP addresses:")
for iface in interfaces:
    try:
        ip = get_if_addr(iface)
        if ip != "0.0.0.0":
            print(f"{iface} → {ip}")
    except:
        pass
