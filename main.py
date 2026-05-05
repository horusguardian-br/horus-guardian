#!/usr/bin/env python3

from banner import show_banner
from modules.scanner import run_scan
from modules.vuln import check_vulnerabilities
from modules.report import generate_report


def menu():
    print("\n[ MENU ]")
    print("[1] Scan de Alvo")
    print("[2] Identificar Vulnerabilidades")
    print("[3] Gerar Relatório")
    print("[0] Sair")


# =========================
# SCAN
# =========================
def executar_scan():
    target = input("\nDigite o IP ou domínio: ")

    results = run_scan(target)

    print("\n[ RESULTADO DO SCAN ]\n")

    for host in results:
        print(f"\nHost: {host}")

        # Mostrar sistema operacional
        if results[host]["os"]:
            print(f"SO provável: {results[host]['os'][0]['name']}")

        # Mostrar portas e serviços
        for service in results[host]["ports"]:
            print(f" - Porta {service['port']} | {service['service']} ({service['version']})")


# =========================
# VULNERABILIDADES
# =========================
def executar_vulnerabilidades():
    target = input("\nDigite o IP ou domínio: ")

    scan_results = run_scan(target)
    vulns = check_vulnerabilities(scan_results)

    print("\n[ VULNERABILIDADES ENCONTRADAS ]\n")

    if not vulns:
        print("Nenhuma vulnerabilidade identificada.")
    else:
        for v in vulns:
            print(f"\nHost: {v['host']}")
            print(f"Risco: {v['risk']}")
            print(f"Severidade: {v['severity']}")
            print(f"CVSS: {v.get('cvss', 'N/A')}")
            print(f"Descrição: {v['description']}")
            print(f"Recomendação: {v['recommendation']}")
            print("-" * 40)


# =========================
# RELATÓRIO
# =========================
def executar_relatorio():
    target = input("\nDigite o IP ou domínio: ")

    scan_results = run_scan(target)
    vulns = check_vulnerabilities(scan_results)

    generate_report(target, scan_results, vulns)


# =========================
# MAIN
# =========================
def main():
    show_banner()

    while True:
        menu()
        option = input("\nEscolha uma opção: ")

        if option == "1":
            executar_scan()

        elif option == "2":
            executar_vulnerabilidades()

        elif option == "3":
            executar_relatorio()

        elif option == "0":
            print("\nSaindo do Horus Guardian...")
            break

        else:
            print("\n[!] Opção inválida. Tente novamente.")


if __name__ == "__main__":
    main()
