import nmap

def scan_network(network_range):
    # Initialize Nmap scanner
    nm = nmap.PortScanner()
    
    # Perform a ping scan (-sn)
    print(f"Scanning network: {network_range}")
    nm.scan(hosts=network_range, arguments='-sn')
    
    # Collect and display results
    active_hosts = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            mac = nm[host]['addresses']['mac']
        else:
            mac = "N/A"
        active_hosts.append({
            'ip': nm[host]['addresses'].get('ipv4', 'N/A'),
            'mac': mac,
            'hostname': nm[host].hostname()
        })

    return active_hosts

if __name__ == "__main__":
    # Replace with your network range (e.g., 192.168.1.0/24)
    network_range = "192.168.1.0/24"
    
    devices = scan_network(network_range)
    
    # Print results
    print("\nActive Devices:")
    for i, device in enumerate(devices, start=1):
        print(f"{i}. IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
