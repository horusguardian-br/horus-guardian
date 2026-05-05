from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os

from modules.risk import calculate_risk_score, classify_risk


def generate_report(target, scan_results, vulnerabilities):

    # Criar pasta se não existir
    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    content = []

    # =========================
    # TÍTULO
    # =========================
    content.append(Paragraph("Horus Guardian - Relatório de Segurança", styles["Title"]))
    content.append(Spacer(1, 12))

    # =========================
    # INFORMAÇÕES GERAIS
    # =========================
    content.append(Paragraph(f"<b>Alvo:</b> {target}", styles["Normal"]))
    content.append(Paragraph(f"<b>Data:</b> {datetime.now()}", styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # RESUMO EXECUTIVO
    # =========================
    score = calculate_risk_score(vulnerabilities)
    risk_level = classify_risk(score)

    content.append(Paragraph("Resumo Executivo", styles["Heading2"]))
    content.append(Paragraph(f"Score de Risco: {score}/100", styles["Normal"]))
    content.append(Paragraph(f"Nível de Risco: {risk_level}", styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # RESULTADOS DO SCAN
    # =========================
    content.append(Paragraph("Resultados do Scan", styles["Heading2"]))

    for host in scan_results:
        content.append(Paragraph(f"<b>Host:</b> {host}", styles["Normal"]))

        for service in scan_results[host]:
            content.append(Paragraph(
                f"Porta {service['port']} - {service['service']} ({service['version']})",
                styles["Normal"]
            ))

    content.append(Spacer(1, 12))

    # =========================
    # VULNERABILIDADES
    # =========================
    content.append(Paragraph("Vulnerabilidades Encontradas", styles["Heading2"]))

    if not vulnerabilities:
        content.append(Paragraph("Nenhuma vulnerabilidade identificada.", styles["Normal"]))
    else:
        for v in vulnerabilities:
            content.append(Paragraph(f"<b>Host:</b> {v['host']}", styles["Normal"]))
            content.append(Paragraph(f"<b>Risco:</b> {v['risk']}", styles["Normal"]))
            content.append(Paragraph(f"<b>Severidade:</b> {v['severity']}", styles["Normal"]))
            content.append(Paragraph(f"<b>CVSS:</b> {v.get('cvss', 'N/A')}", styles["Normal"]))
            content.append(Paragraph(f"<b>Descrição:</b> {v['description']}", styles["Normal"]))
            content.append(Paragraph(f"<b>Recomendação:</b> {v['recommendation']}", styles["Normal"]))
            content.append(Spacer(1, 10))

    # =========================
    # FINALIZAR PDF
    # =========================
    doc.build(content)

    print(f"\n[+] Relatório gerado em: {filename}")
