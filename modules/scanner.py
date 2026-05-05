import nmap
import os
import json
from datetime import datetime


def run_scan(target):
    nm = nmap.PortScanner()

    print(f"[+] Iniciando scan em {target}...\n")

    try:
        nm.scan(hosts=target, arguments='-sS -sV -O -T4 -Pn --script vuln')
    except Exception as e:
        print(f"[ERRO] Falha ao executar scan: {e}")
        return {}

    results = {}

    for host in nm.all_hosts():

        # =========================
        # SISTEMA OPERACIONAL
        # =========================
        os_info = nm[host].get('osmatch', [])

        results[host] = {
            "os": os_info,
            "ports": []
        }

        # =========================
        # PORTAS / SERVIÇOS
        # =========================
        for proto in nm[host].all_protocols():

            ports = nm[host][proto].keys()

            for port in ports:

                try:
                    port_data = nm[host][proto][port]
                except KeyError:
                    continue

                service = port_data.get('name', '')
                version = port_data.get('version', '')
                product = port_data.get('product', '')
                extrainfo = port_data.get('extrainfo', '')
                state = port_data.get('state', '')

                # =========================
                # SCRIPTS DO NMAP (VULN, BANNER, ETC)
                # =========================
                scripts = port_data.get('script', {})

                results[host]["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extra": extrainfo,
                    "scripts": scripts
                })

    save_log(target, results)

    return results


# =========================
# SALVAR LOG
# =========================
def save_log(target, results):

    if not os.path.exists("logs"):
        os.makedirs("logs")

    filename = f"logs/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

        print(f"\n[+] Log salvo em: {filename}")

    except Exception as e:
        print(f"[ERRO] Falha ao salvar log: {e}")
