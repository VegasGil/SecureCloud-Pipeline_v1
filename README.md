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
# deativate

python.exe -m pip install --upgrade pip
pip install -r requirements.txt


## Estado del pipeline (intencionalmente en rojo)

Los workflows `SAST CI` y `SCA CI` **fallan a propósito**. `app/main.py` y 
`app/requirements.txt` contienen vulnerabilidades deliberadas para demostrar 
que el pipeline las detecta y bloquea:

- **SAST (Semgrep)**: command injection (`shell=True`), `eval()` sobre input externo.
- **SCA (Trivy)**: dependencias antiguas con CVEs conocidas (flask 0.12.2, pyyaml 3.13…).
- **IaC (Checkov)**: bucket S3 público, pod privilegiado como root.

El objetivo del proyecto es mostrar el **pipeline de detección**, no un código limpio. 
Los fixes se aplican al final de la Fase 2 como cierre del ciclo.

### Workflows activos
- `detection-ci.yml` → valida reglas Sigma (Fase 1).
- `sast-ci.yml` → Semgrep sobre `app/` (Fase 2).
- `sca-ci.yml` → Trivy sobre `app/` (Fase 2, próximamente).
![semgrep](semgrep.png)