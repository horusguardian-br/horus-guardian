from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
import os

from modules.risk import calculate_risk_score, classify_risk


def generate_report(target, scan_results, vulnerabilities):

    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    content = []

    # =========================
    # CAPA
    # =========================
    content.append(Paragraph("HORUS GUARDIAN", styles["Title"]))
    content.append(Spacer(1, 20))
    content.append(Paragraph("Relatório Técnico de Segurança da Informação", styles["Heading2"]))
    content.append(Spacer(1, 30))

    content.append(Paragraph(f"<b>Alvo:</b> {target}", styles["Normal"]))
    content.append(Paragraph(f"<b>Data:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]))
    content.append(Paragraph("<b>Responsáveis:</b> João Paulo Márinho / Vivianne Stefany Santos", styles["Normal"]))

    content.append(Spacer(1, 40))
    content.append(Paragraph("Confidencial – Uso restrito", styles["Normal"]))

    content.append(PageBreak())

    # =========================
    # IDENTIFICAÇÃO
    # =========================
    content.append(Paragraph("1. Identificação", styles["Heading2"]))
    content.append(Paragraph(
        "Relatório técnico elaborado com base em análise automatizada de segurança da informação utilizando a ferramenta Horus Guardian.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # OBJETIVO
    # =========================
    content.append(Paragraph("2. Objetivo", styles["Heading2"]))
    content.append(Paragraph(
        "Identificar vulnerabilidades, classificar riscos e priorizar ações corretivas.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # METODOLOGIA
    # =========================
    content.append(Paragraph("3. Metodologia", styles["Heading2"]))
    content.append(Paragraph(
        "Foram utilizadas técnicas de varredura de rede, identificação de serviços, correlação com CVEs e análise baseada em CVSS.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # LIMITAÇÕES
    # =========================
    content.append(Paragraph("4. Limitações", styles["Heading2"]))
    content.append(Paragraph(
        "A análise possui caráter não intrusivo, podendo não identificar vulnerabilidades que dependam de autenticação ou exploração ativa.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # RESULTADOS TÉCNICOS
    # =========================
    content.append(Paragraph("5. Resultados Técnicos", styles["Heading2"]))

    for host in scan_results:
        content.append(Paragraph(f"<b>Host:</b> {host}", styles["Normal"]))

        if scan_results[host]["os"]:
            content.append(Paragraph(
                f"<b>SO:</b> {scan_results[host]['os'][0]['name']}",
                styles["Normal"]
            ))

        for service in scan_results[host]["ports"]:
            content.append(Paragraph(
                f"Porta {service['port']} ({service['protocol']}) - {service['service']} "
                f"({service['product']} {service['version']}) - {service['state']}",
                styles["Normal"]
            ))

    content.append(Spacer(1, 12))

    # =========================
    # TABELA DE VULNERABILIDADES
    # =========================
    content.append(Paragraph("6. Vulnerabilidades Identificadas", styles["Heading2"]))

    if not vulnerabilities:
        content.append(Paragraph("Nenhuma vulnerabilidade relevante identificada.", styles["Normal"]))
    else:
        table_data = [["Host", "Risco", "Severidade", "Prioridade", "CVSS"]]

        for v in vulnerabilities:
            table_data.append([
                v['host'],
                v['risk'],
                v['severity'],
                v.get('priority', 'N/A'),
                str(v.get('cvss', 'N/A'))
            ])

        table = Table(table_data, repeatRows=1)

        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.black),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),

            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),

            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
        ]))

        content.append(table)
        content.append(Spacer(1, 20))

    # =========================
    # ANÁLISE DE RISCO
    # =========================
    score = calculate_risk_score(vulnerabilities)
    risk_level = classify_risk(score)

    content.append(Paragraph("7. Análise de Risco", styles["Heading2"]))
    content.append(Paragraph(f"<b>Score Geral:</b> {score}/100", styles["Normal"]))
    content.append(Paragraph(f"<b>Nível de Risco:</b> {risk_level}", styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # GRÁFICO DE RISCO
    # =========================
    content.append(Paragraph("Gráfico de Risco (CVSS)", styles["Heading3"]))

    if vulnerabilities:
        cvss_values = [v.get("cvss", 0) or 0 for v in vulnerabilities]

        drawing = Drawing(400, 200)

        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.height = 125
        chart.width = 300

        chart.data = [cvss_values[:10]]
        chart.categoryAxis.categoryNames = [f"V{i+1}" for i in range(len(cvss_values[:10]))]

        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = 10
        chart.valueAxis.valueStep = 2

        drawing.add(chart)

        content.append(drawing)
        content.append(Spacer(1, 20))

    # =========================
    # RECOMENDAÇÕES
    # =========================
    content.append(Paragraph("8. Recomendações", styles["Heading2"]))
    content.append(Paragraph(
        "Priorizar correção das vulnerabilidades classificadas como CRÍTICA e ALTA, "
        "especialmente aquelas expostas à internet.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # CONCLUSÃO
    # =========================
    content.append(Paragraph("9. Conclusão Técnica", styles["Heading2"]))
    content.append(Paragraph(
        "A análise identificou vulnerabilidades relevantes, sendo recomendada ação imediata "
        "para mitigação dos riscos mais críticos.",
        styles["Normal"]))
    content.append(Spacer(1, 12))

    # =========================
    # DISCLAIMER
    # =========================
    content.append(Paragraph("10. Disclaimer Jurídico", styles["Heading2"]))
    content.append(Paragraph(
        "Este relatório foi elaborado com base em análise técnica autorizada. "
        "Não incentiva práticas ilícitas. "
        "Atende aos princípios da LGPD e do Marco Civil da Internet, garantindo segurança, privacidade e legalidade.",
        styles["Normal"]))

    doc.build(content)

    print(f"\n[+] Relatório profissional gerado em: {filename}")
