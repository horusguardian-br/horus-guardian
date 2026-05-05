def calculate_risk_score(vulnerabilities):
    if not vulnerabilities:
        return 0

    total_cvss = 0
    count = 0

    for v in vulnerabilities:
        cvss = v.get("cvss")

        if cvss:
            total_cvss += cvss
            count += 1

    if count == 0:
        return 10  # fallback mínimo

    # Média CVSS (0 a 10) convertida para escala 0–100
    score = (total_cvss / count) * 10

    if score > 100:
        score = 100

    return int(score)


def classify_risk(score):
    if score >= 80:
        return "CRÍTICO"
    elif score >= 60:
        return "ALTO"
    elif score >= 40:
        return "MÉDIO"
    elif score >= 20:
        return "BAIXO"
    else:
        return "MÍNIMO"
