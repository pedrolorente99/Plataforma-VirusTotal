"""Genera archivos INOFENSIVOS para probar el modo demo en la carpeta muestras_demo/."""
from pathlib import Path

d = Path(__file__).parent / "muestras_demo"
d.mkdir(exist_ok=True)
eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
(d / "prueba_eicar.txt").write_text(eicar)                      # fichero de prueba estándar de antivirus
(d / "factura.pdf.exe").write_bytes(b"texto inofensivo")        # doble extensión engañosa
(d / "script_sospechoso.ps1").write_text("# solo texto de ejemplo\npowershell -enc AAAA\nIEX (New-Object Net.WebClient).DownloadString('x')\n")
(d / "informe_limpio.txt").write_text("Este archivo es normal y no debería marcarse.\n")
print(f"Muestras creadas en {d}")
