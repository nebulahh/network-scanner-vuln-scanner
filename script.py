import nmap
import requests

nm = nmap.PortScanner()
target_ip = 'ip'
port_range = '22-443'

nm.scan(target_ip, port_range, arguments='-sV')

def check_vuln(service_name, port, version=None):
    query = f"{service_name} {port}"
    if version:
        query += f" {version}"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data and len(data['vulnerabilities']) > 0:
                return data['vulnerabilities']
            else:
                return f"No vulnerabilities found for {query}."
        else:
            return f"Error fetching data from CVE API: {response.status_code}"
    except requests.RequestException as e:
        return f"Request failed: {e}" 

print(f"Scan results for {target_ip}:")
for proto in nm[target_ip].all_protocols():
    print(f"Protocol : {proto}")
    ports = nm[target_ip][proto].keys()
    for port in ports:
        info = nm[target_ip][proto][port]
        if info['state'] == 'open':
            vuln = check_vuln(info.get('name', ''), port, info.get('version', ''))
            if vuln:
                print(f"Vulnerabilities found for {info['name']} {port}:")
                for item in vuln:
                    print(item)
            else:
                return vuln