import nmap

nm = nmap.PortScanner()
target_ip = '' 
port_range = '22-443'

nm.scan(target_ip, port_range, arguments='-sV')

print(f"Scan results for {target_ip}:")
for proto in nm[target_ip].all_protocols():
    print(f"Protocol : {proto}")
    ports = nm[target_ip][proto].keys()
    for port in ports:
        info = nm[target_ip][proto][port]
        print(f"Port: {port}----State: {info['state']}----Service: {info.get('name', '')}----Version: {info.get('version', '')}")