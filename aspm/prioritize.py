"""Cruza hallazgos de Trivy con EPSS y CISA KEV para priorizar por riesgo real."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRIVY_JSON = ROOT / "app_trivy.json"
EPSS_JSON = Path(__file__).parent / "data" / "epss.json"
KEV_JSON = Path(__file__).parent / "data" / "kev.json"

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "UNKNOWN": 0}


def load_json(path):
    if not path.exists():
        raise SystemExit(f"Falta {path}. Ejecuta fetch_sources.py y trivy primero.")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def calculate_risk(severity: str, epss: float, in_kev: bool) -> float:
    """Fórmula simple pero realista:
    Score base por severidad + peso por probabilidad EPSS + bonus masivo si está en KEV.
    """
    base = SEVERITY_WEIGHT.get(severity.upper(), 0)
    epss_score = epss * 10
    kev_bonus = 20 if in_kev else 0
    return base + epss_score + kev_bonus


def main():
    print("[*] Cargando datos de EPSS y KEV...")
    epss_db = load_json(EPSS_JSON)
    kev_db = set(load_json(KEV_JSON))
    
    print("[*] Cargando resultados de Trivy...")
    trivy_data = load_json(TRIVY_JSON)

    findings = []
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            sev = vuln.get("Severity", "UNKNOWN")
            
            # Buscar en EPSS y KEV
            epss_val = epss_db.get(cve, 0.0)
            in_kev = cve in kev_db
            
            risk_score = calculate_risk(sev, epss_val, in_kev)
            
            findings.append({
                "cve": cve,
                "package": pkg,
                "severity": sev,
                "epss": epss_val,
                "kev": in_kev,
                "risk_score": risk_score
            })

    # Ordenar por Risk Score de mayor a menor
    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    # Imprimir tabla
    print("\n=== RANKING DE RIESGO (ASPM) ===\n")
    print(f"{'CVE':<16} | {'Paquete':<12} | {'Sev':<8} | {'EPSS':<6} | {'KEV':<3} | {'Risk':<4}")
    print("-" * 65)
    
    for f in findings:
        kev_str = "SÍ" if f["kev"] else "no"
        print(f"{f['cve']:<16} | {f['package']:<12} | {f['severity']:<8} | {f['epss']:<6.3f} | {kev_str:<3} | {f['risk_score']:<4.1f}")

    print(f"\nTotal vulnerabilidades evaluadas: {len(findings)}")


if __name__ == "__main__":
    main()