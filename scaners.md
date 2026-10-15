# A. Venv separado solo para scanners (recomendado):

powershell
python -m venv .venv-scanners
.\.venv-scanners\Scripts\activate
pip install checkov
checkov --version

pip install --user checkov