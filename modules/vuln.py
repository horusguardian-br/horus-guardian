from modules.cve import search_cve


# =========================
# FUNÇÃO DE PRIORIDADE INTELIGENTE
# =========================
def calculate_priority(cvss, port):
    score = cvss or 0

    # Serviços críticos expostos aumentam prioridade
    if port in [21, 23, 3389, 445]:
        score += 1.5

    if score >= 9:
        return "CRÍTICA"
    elif score >= 7:
        return "ALTA"
    elif score >= 4:
        return "MÉDIA"
    else:
        return "BAIXA"


# =========================
# FUNÇÃO PRINCIPAL
# =========================
def check_vulnerabilities(scan_results):

    vulnerabilities = []

    for host in scan_results:

        for service in scan_results[host]["ports"]:

            port = service.get("port")
            name = service.get("service", "")
            product = service.get("product", "")
            version = service.get("version", "")
            state = service.get("state", "")
            scripts = service.get("scripts", {})

            # =========================
            # IGNORAR PORTAS FECHADAS
            # =========================
            if state != "open":
                continue

            # =========================
            # REGRAS BÁSICAS
            # =========================

            # FTP
            if port == 21:
                cvss = 7.5
                vulnerabilities.append({
                    "host": host,
                    "risk": "FTP exposto",
                    "severity": "ALTA",
                    "cvss": cvss,
                    "priority": calculate_priority(cvss, port),
                    "description": "Serviço FTP exposto pode permitir acesso não autorizado.",
                    "recommendation": "Desabilitar ou substituir por SFTP."
                })

            # Telnet
            if port == 23:
                cvss = 9.0
                vulnerabilities.append({
                    "host": host,
                    "risk": "Telnet ativo (inseguro)",
                    "severity": "CRÍTICA",
                    "cvss": cvss,
                    "priority": calculate_priority(cvss, port),
                    "description": "Telnet transmite dados sem criptografia.",
                    "recommendation": "Substituir por SSH."
                })

            # RDP
            if port == 3389:
                cvss = 8.0
                vulnerabilities.append({
                    "host": host,
                    "risk": "RDP exposto",
                    "severity": "ALTA",
                    "cvss": cvss,
                    "priority": calculate_priority(cvss, port),
                    "description": "Serviço RDP exposto pode ser alvo de ataques brute force.",
                    "recommendation": "Restringir acesso via firewall ou VPN."
                })

            # SMB
            if port == 445:
                cvss = 8.5
                vulnerabilities.append({
                    "host": host,
                    "risk": "SMB exposto",
                    "severity": "ALTA",
                    "cvss": cvss,
                    "priority": calculate_priority(cvss, port),
                    "description": "Serviço SMB exposto pode permitir exploração remota.",
                    "recommendation": "Restringir acesso e aplicar patches de segurança."
                })

            # =========================
            # SCRIPTS DO NMAP
            # =========================
            for script_name, script_output in scripts.items():

                cvss = 7.0

                vulnerabilities.append({
                    "host": host,
                    "risk": f"Script detectou vulnerabilidade ({script_name})",
                    "severity": "ALTA",
                    "cvss": cvss,
                    "priority": calculate_priority(cvss, port),
                    "description": str(script_output),
                    "recommendation": "Analisar saída do script e aplicar correções específicas."
                })

            # =========================
            # CVE REAL
            # =========================
            if product:

                cves = search_cve(product, version)

                for cve in cves:

                    cvss = cve.get("cvss", 0) or 0
                    priority = calculate_priority(cvss, port)

                    if cvss >= 9:
                        severity = "CRÍTICA"
                    elif cvss >= 7:
                        severity = "ALTA"
                    elif cvss >= 4:
                        severity = "MÉDIA"
                    else:
                        severity = "BAIXA"

                    vulnerabilities.append({
                        "host": host,
                        "risk": f"CVE detectada: {cve.get('cve')}",
                        "severity": severity,
                        "cvss": cvss,
                        "priority": priority,
                        "description": cve.get("summary", ""),
                        "recommendation": "Atualizar o serviço para versão corrigida."
                    })

    return vulnerabilities
