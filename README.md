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

## Vulnerabilidades deliberadas

- **SAST (Semgrep)**: command injection (`shell=True`), `eval()`.

![semgrep](/docs/semgrep.png)

- **SCA (Trivy)**: pyyaml 3.13 (CVE-2017-18342, CRITICAL), flask 0.12.2, 
  jinja2 2.10, requests 2.19.0 (5 HIGH + 2 CRITICAL).

![sca vulnerabilidad](/docs/sca.png)
![sca vulnerabilidad](/docs/sca1.png)