from modules.cve import search_cve

def check_vulnerabilities(scan_results):
    vulnerabilities = []

    for host in scan_results:
        for service in scan_results[host]["ports"]:

            port = service["port"]
            name = service["service"]
            product = service.get("product", "")
            version = service.get("version", "")

            # 🔹 Regras básicas
            if port == 21:
                vulnerabilities.append({
                    "host": host,
                    "risk": "FTP aberto",
                    "severity": "ALTA",
                    "description": "Serviço FTP pode permitir acesso não autorizado.",
                    "recommendation": "Desabilitar ou usar SFTP."
                })

            # 🔥 CVE REAL
            cves = search_cve(product, version)

            for cve in cves:
                cvss = cve.get("cvss", 0) or 0

                vulnerabilities.append({
                    "host": host,
                    "risk": f"CVE encontrada: {cve['cve']}",
                    "severity": "CRÍTICA" if cvss >= 9 else "ALTA" if cvss >= 7 else "MÉDIA",
                    "cvss": cvss,
                    "description": cve["summary"],
                    "recommendation": "Atualizar serviço para versão segura."
    })
