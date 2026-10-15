# SecureCloud-Pipeline_v1
Objetivo concreto Crear la estructura inicial del proyecto SecureCloud-Pipeline, instalar sigma-cli y validar una primera regla Sigma local.


mkdir SecureCloud-Pipeline
cd SecureCloud-Pipeline
git init

mkdir -p detections/windows tests

python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
# deactivate

python.exe -m pip install --upgrade pip
pip install -r requirements.txt

## Hallazgos detectados por el pipeline

### SAST — Semgrep
\`\`\`
app/main.py
  python.lang.security.audit.dangerous-subprocess-use
  python.lang.security.audit.eval-detected
\`\`\`

### SCA — Trivy
| Librería | CVE | Severidad | Fix |
|---|---|---|---|
| pyyaml 3.13 | CVE-2017-18342 | CRITICAL | 5.1 |
| flask 0.12.2 | CVE-2018-1000656 | HIGH | 0.12.3 |
...

### IaC — Checkov
- Terraform: 11 FAILED (`CKV_AWS_20`, `CKV_AWS_24`, `CKV2_AWS_6`...)
- Kubernetes: 20 FAILED (`CKV_K8S_16`, `CKV_K8S_23`, `CKV_K8S_14`...)