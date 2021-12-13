from ipaddress import ip_address, IPv6Address
import os

def make_multicast_mac(target_ipv6: str):
   map_addr = int(IPv6Address(target_ipv6))
   map_addr = map_addr & 0xFFFFFFFF
   multicast_mac = '3333.%04X.%04X' %(map_addr >> 16, map_addr & 0xFFFF)
   return multicast_mac

def mac_to_colon_notation(mac):
    mac = mac.replace('.', '')
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

def make_link_local_ipv6(mac: str):
    mac = mac_to_colon_notation(mac)
    parts = mac.split(":")

    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::%s" % (":".join(ipv6Parts))
    return ipv6

def convert_ip_to_int(ip_addr: str):
    return int(ip_address(ip_addr))

def pad_hex_num(num, pad_max_length, add_prefix=False):
    if add_prefix:
        res = f'{num:#0{pad_max_length}x}'
    else:
        res = f'{num:0{pad_max_length}x}'
    return res

def get_template_path():
    return os.path.dirname(__file__) + '/templates'
