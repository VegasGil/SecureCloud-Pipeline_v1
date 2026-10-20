# SecureCloud-Pipeline

[![Detection CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/detection-ci.yml)
[![SAST CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/sast-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/sast-ci.yml)
[![SCA CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/sca-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/sca-ci.yml)
[![IaC CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/iac-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/iac-ci.yml)

Pipeline incremental de seguridad que combina **Detection-as-Code**, **DevSecOps** y **gestión de exposición** sobre un stack Terraform + Kubernetes + Python.

## Pipeline de seguridad (6 capas activas)

| Capa | Herramienta | Workflow | Objetivo |
|---|---|---|---|
| Detection-as-Code | Sigma + pytest | `detection-ci.yml` | Reglas de detección versionadas y validadas |
| SAST | Semgrep | `sast-ci.yml` | Patrones inseguros en código Python |
| SCA | Trivy | `sca-ci.yml` | CVEs en dependencias |
| IaC | Checkov | `iac-ci.yml` | Misconfiguraciones en Terraform + Kubernetes |
| ASPM | Trivy + EPSS + KEV | `aspm-ci.yml` | Priorización de CVEs por riesgo real de explotación |
| Runtime Security | Falco | `falco-ci.yml` | Detección en caliente (ej. shell en contenedor) |

## Estructura del repositorio

```text
.
├── .github/workflows/    # CI: detection, SAST, SCA, IaC, ASPM, Falco
├── app/                  # App demo Python (target de SAST/SCA)
├── aspm/                 # Motor de priorización (EPSS + KEV)
├── falco/rules/          # Reglas de runtime security
├── infra/                # Terraform (target de Checkov)
├── k8s/                  # Manifiestos K8s (target de Checkov)
├── detections/windows/   # Reglas Sigma
├── tests/                # Tests de reglas Sigma con eventos sintéticos
├── .pre-commit-config.yaml
└── requirements.txt

## Hallazgos detectados (vulnerabilidades deliberadas)

> Los workflows SAST/SCA/IaC **fallan a propósito**: el código contiene vulnerabilidades
> para demostrar que el pipeline las detecta y bloquea.

### SAST — Semgrep
- `python.lang.security.audit.dangerous-subprocess-use` — command injection (`shell=True`)
- `python.lang.security.audit.eval-detected` — `eval()` sobre input externo

### SCA — Trivy
| Librería | CVE | Severidad | Fix |
|---|---|---|---|
| pyyaml 3.13 | CVE-2017-18342 | CRITICAL | 5.1 |
| pyyaml 3.13 | CVE-2020-14343 | CRITICAL | 5.4 |
| flask 0.12.2 | CVE-2018-1000656 | HIGH | 0.12.3 |
| flask 0.12.2 | CVE-2023-30861 | HIGH | 2.3.2 |
| jinja2 2.10 | CVE-2019-10906 | HIGH | 2.10.1 |
| requests 2.19.0 | CVE-2018-18074 | HIGH | 2.20.0 |

### IaC — Checkov
- **Terraform** (11 FAILED): `CKV_AWS_20` (S3 público), `CKV_AWS_24` (SSH abierto 0.0.0.0/0), `CKV2_AWS_6` (sin Public Access Block), `CKV_AWS_19/21/145` (sin cifrado/versionado/KMS)
- **Kubernetes** (20 FAILED): `CKV_K8S_16` (privileged), `CKV_K8S_23` (root), `CKV_K8S_14` (imagen `latest`), `CKV_K8S_10/11/12/13` (sin límites CPU/memoria)

| ASPM | Trivy + EPSS + KEV | `aspm-ci.yml` | Priorización de CVEs por riesgo real de explotación |

### ASPM — Priorización por riesgo real (EPSS + KEV)

Las herramientas tradicionales priorizan por severidad (`CRITICAL`, `HIGH`). Este pipeline va un paso más allá y cruza las vulnerabilidades de Trivy con:
- **EPSS**: Probabilidad (0-100%) de que una CVE sea explotada en los próximos 30 días.
- **CISA KEV**: Catálogo de vulnerabilidades que ya se están explotando activamente en el mundo real.

El script `aspm/prioritize.py` genera un **Risk Score** combinando: `Severidad (peso base) + EPSS (probabilidad) + KEV (+20 pts si es explotada activamente)`.

## Ejemplo de ranking generado en el CI:
| CVE | Paquete | Sev | EPSS | KEV | Risk Score |
|---|---|---|---|---|---|
| CVE-2020-14343 | pyyaml | CRITICAL | 0.060 | no | 10.6 |
| CVE-2017-18342 | pyyaml | CRITICAL | 0.057 | no | 10.6 |
| CVE-2018-18074 | requests | HIGH | 0.074 | no | 7.7 |



### Runtime Security — Falco

Mientras que SAST, SCA y IaC analizan el código *antes* de desplegar, Falco detecta amenazas *en tiempo de ejecución* (Runtime). 
En este proyecto validamos una regla custom de Detection-as-Code (`falco/rules/custom_rules.yaml`) que alerta si se abre una terminal interactiva dentro de un contenedor Kubernetes.

## Cómo ejecutar en local

\`\`\`bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# Reglas Sigma
sigma check --fail-on-issues detections/
pytest -v
\`\`\`