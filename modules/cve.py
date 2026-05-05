import requests


def search_cve(product, version):
    vulns = []

    if not product:
        return vulns

    query = f"{product} {version}"

    try:
        url = f"https://cve.circl.lu/api/search/{product}/{version}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()

            for item in data.get("data", [])[:5]:  # limita a 5 resultados
                vulns.append({
                    "cve": item.get("id"),
                    "summary": item.get("summary"),
                    "cvss": item.get("cvss")
                })

    except Exception:
        pass

    return vulns
