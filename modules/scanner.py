import nmap
from datetime import datetime
import json
import os


def run_scan(target):
    nm = nmap.PortScanner()

    print(f"[+] Escaneando {target}...\n")

    # Scan avançado
    nm.scan(hosts=target, arguments='-sS -sV -O -T4 -Pn --script vuln')

    results = {}

    for host in nm.all_hosts():

        # Coletar sistema operacional
        os_info = nm[host].get('osmatch', [])

        results[host] = {
            "os": os_info,
            "ports": []
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()

            for port in ports:

                port_data = nm[host][proto][port]

                service = port_data.get('name', '')
                version = port_data.get('version', '')
                product = port_data.get('product', '')
                extrainfo = port_data.get('extrainfo', '')

                results[host]["ports"].append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "product": product,
                    "extra": extrainfo
                })

    save_log(target, results)

    return results


def save_log(target, results):
    if not os.path.exists("logs"):
        os.makedirs("logs")

    filename = f"logs/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Log salvo em {filename}")
