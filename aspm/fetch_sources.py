"""Descarga EPSS y CISA KEV a aspm/data/."""
import json
import gzip
import urllib.request
from pathlib import Path

DATA = Path(__file__).parent / "data"
DATA.mkdir(exist_ok=True)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_epss() -> dict:
    """Devuelve {cve: epss_score} como dict ligero."""
    out = {}
    with urllib.request.urlopen(EPSS_URL, timeout=60) as resp:
        with gzip.open(resp, "rt", encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or line.startswith("cve,"):
                    continue
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    out[parts[0]] = float(parts[1])
    (DATA / "epss.json").write_text(json.dumps(out))
    return out


def fetch_kev() -> set:
    """Devuelve el conjunto de CVEs en CISA KEV."""
    with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
    (DATA / "kev.json").write_text(json.dumps(sorted(cves)))
    return cves


if __name__ == "__main__":
    epss = fetch_epss()
    kev = fetch_kev()
    print(f"EPSS: {len(epss)} CVEs descargadas")
    print(f"KEV:  {len(kev)} CVEs confirmadas como explotadas")
    print(f"Ejemplo EPSS CVE-2017-18342: {epss.get('CVE-2017-18342', 'no encontrada')}")
    print(f"¿CVE-2017-18342 en KEV? {'SÍ' if 'CVE-2017-18342' in kev else 'no'}")