# 🛡️ Horus Guardian

Ferramenta de Pentest e Análise de Vulnerabilidades com integração de CVE e geração de relatórios.

## 🚀 Funcionalidades

- 🔍 Scan de rede com Nmap
- 🧠 Identificação de vulnerabilidades
- 🌐 Integração com CVEs reais
- 📊 Score de risco com CVSS
- 📄 Geração de relatórios em PDF
🔹 3. O que a ferramenta faz

O Horus Guardian é uma plataforma de análise de segurança ofensiva e avaliação de risco, capaz de:

    Realizar varredura de rede (port scanning)
    Identificar serviços ativos e versões
    Detectar sistema operacional do alvo
    Identificar vulnerabilidades conhecidas
    Correlacionar serviços com CVE reais
    Calcular risco com base em CVSS
    Gerar relatórios técnicos automatizados 

🔹 1. Principais recursos disponíveis
🔍 Scanner Avançado

    Varredura com técnicas stealth
    Identificação de portas, serviços e versões
    Detecção de sistema operacional
    Execução de scripts de vulnerabilidade do Nmap 

🧠 Análise Inteligente de Vulnerabilidades

    Regras baseadas em exposição de serviços
    Correlação automática com CVEs reais
    Classificação por severidade (CRÍTICA, ALTA, MÉDIA…) 

🌐 Integração com CVE

    Consulta a bancos públicos de vulnerabilidades
    Retorno de:
        ID da CVE
        Descrição
        Score CVSS 

📊 Sistema de Score de Risco

    Baseado em média de CVSS
    Escala de 0 a 100
    Classificação automática:
        CRÍTICO
        ALTO
        MÉDIO
        BAIXO 

📄 Relatório Profissional

    Geração automática em PDF
    Estrutura contendo:
        Resumo executivo
        Score de risco
        Detalhamento técnico
        Recomendações 

🧾 Sistema de Logs

    Armazenamento em JSON
    Histórico de análises
    Base para auditoria e rastreabilidade 

🔹 2. Por que a ferramenta é eficaz
✔ Integra múltiplas camadas de análise

Não depende apenas de portas abertas — correlaciona:

    Serviço
    Versão
    Vulnerabilidade real 

✔ Baseada em padrões internacionais

Utiliza:

    CVE (Common Vulnerabilities and Exposures)
    CVSS (Common Vulnerability Scoring System) 

👉 Mesmo padrão usado por:

    Nessus
    Qualys 

✔ Automatiza processos complexos

Reduz tempo de análise manual e:

    Identifica riscos rapidamente
    Sugere ações corretivas 


## ⚙️ Instalação

```bash
git clone https://github.com/seuusuario/horus-guardian.git
cd horus-guardian

pip install -r requirements.txt

## ▶️ Uso

python3 main.py
