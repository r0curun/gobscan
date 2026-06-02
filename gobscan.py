#!/usr/bin/env python3
"""
GobScan - Detección y reporte de sitios .gob infectados con spam SEO blackhat
Uso ético — Solo para reportar vulnerabilidades responsablemente
"""

import argparse
import json
import csv
import time
import sys
import os
import webbrowser
import urllib.parse
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── Colores ANSI ─────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
B  = "\033[1m"
D  = "\033[2m"
X  = "\033[0m"

# ─── Dominios gubernamentales ─────────────────────────────────────────────────
GOV_DOMAINS = {
    "ec":  ".gob.ec",
    "pe":  ".gob.pe",
    "bo":  ".gob.bo",
    "co":  ".gov.co",
    "mx":  ".gob.mx",
    "ar":  ".gob.ar",
    "cl":  ".gob.cl",
    "ve":  ".gob.ve",
    "py":  ".gov.py",
    "uy":  ".gub.uy",
    "br":  ".gov.br",
}

# ─── Presets de dorks ─────────────────────────────────────────────────────────
# Cada preset tiene: descripción + lista de palabras clave base
DORK_PRESETS = {
    "1": {
        "name": "Casino / Apuestas",
        "keywords": ["casino", "poker", "slots", "apuestas", "ruleta",
                     "tragamonedas", "blackjack", "baccarat", "bingo online"],
        "desc": "Spam de casinos y apuestas online (el más común en .gob.ec)"
    },
    "2": {
        "name": "Farmacia / Pharma",
        "keywords": ["viagra", "cialis", "pharmacy", "farmacia", "levitra",
                     "sildenafil", "buy cheap pills", "online drugstore"],
        "desc": "Inyección de spam farmacéutico"
    },
    "3": {
        "name": "Crypto / Inversiones",
        "keywords": ["bitcoin", "crypto", "binance", "investment", "trading",
                     "earn money online", "passive income", "forex"],
        "desc": "Spam de criptomonedas e inversiones fraudulentas"
    },
    "4": {
        "name": "Préstamos / Finanzas",
        "keywords": ["prestamos", "credito rapido", "loan", "payday loan",
                     "dinero rapido", "prestamo sin buro"],
        "desc": "Spam de préstamos y servicios financieros dudosos"
    },
    "5": {
        "name": "Archivos PHP sospechosos",
        "keywords": [],
        "extra_dork": 'filetype:php inurl:upload OR inurl:shell OR inurl:cmd OR inurl:backdoor',
        "desc": "Posibles webshells o scripts maliciosos subidos al servidor"
    },
    "6": {
        "name": "Directorios expuestos",
        "keywords": [],
        "extra_dork": 'intitle:"index of" "wp-content" OR ".env" OR "backup" OR "config"',
        "desc": "Directorios públicos con archivos sensibles"
    },
    "7": {
        "name": "WordPress mal configurado",
        "keywords": [],
        "extra_dork": 'inurl:"/wp-json/wp/v2/users" OR inurl:"/wp-admin/install.php"',
        "desc": "Instalaciones WordPress con endpoints de usuario expuestos"
    },
    "8": {
        "name": "Redirecciones sospechosas",
        "keywords": [],
        "extra_dork": 'inurl:redirect OR inurl:"?url=" OR inurl:"?goto=" OR inurl:"?link="',
        "desc": "Parámetros de redirección que pueden usarse para phishing"
    },
    "9": {
        "name": "Títulos comprometidos",
        "keywords": ["casino", "poker", "viagra", "bitcoin", "buy cheap"],
        "use_intitle": True,
        "desc": "Páginas cuyo título fue reemplazado por spam (señal clara de hackeo)"
    },
}

# ─── Canales de reporte ───────────────────────────────────────────────────────
REPORT_CHANNELS = {
    "CERT-EC":          "https://www.ecucert.gob.ec/reportar",
    "CERT LACNIC":      "https://lacnic.net/4983/2/lacnic/cert-lacnic",
    "Google Safe Brow.":"https://safebrowsing.google.com/safebrowsing/report_phish/",
    "URLhaus":          "https://urlhaus.abuse.ch/",
    "Abuse.ch":         "https://abuse.ch/",
}


def banner():
    print(f"""{C}{B}
  ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║  ███╗██║   ██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║   ██║██║   ██║██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{X}{D}  Detección y reporte de sitios .gob infectados con spam SEO blackhat
  Uso ético — Solo para reportar vulnerabilidades responsablemente
{X}""")


def build_dork(domain_suffix: str, preset: dict, extra_words: list[str]) -> str:
    """Construye el dork final combinando preset + palabras extra del usuario."""

    # Presets con dork fijo (shells, directorios, WP, redirects)
    if "extra_dork" in preset:
        return f"site:{domain_suffix} {preset['extra_dork']}"

    # Presets con intitle
    if preset.get("use_intitle"):
        all_kw = preset["keywords"] + extra_words
        terms = " OR ".join(f'"{w}"' for w in all_kw)
        return f"site:{domain_suffix} intitle:{terms}"

    # Presets normales con intext
    all_kw = preset["keywords"] + extra_words
    terms = " OR ".join(f'"{w}"' for w in all_kw)
    return f"site:{domain_suffix} intext:{terms}"


def open_and_search(dork: str):
    """Abre el dork en Google en el navegador del usuario."""
    encoded = urllib.parse.quote(dork)
    url = f"https://www.google.com/search?q={encoded}&num=30"
    webbrowser.open(url)
    return url


def verify_url(url: str, timeout: int = 8) -> dict:
    """Verifica si la URL sigue infectada."""
    info = {"reachable": False, "status_code": None,
            "has_infection": False, "keywords_found": []}
    if not REQUESTS_AVAILABLE:
        return info

    all_keywords = [
        "casino", "poker", "slots", "apuestas", "ruleta", "tragamonedas",
        "viagra", "cialis", "pharmacy", "farmacia", "bitcoin", "crypto",
        "binance", "prestamo", "loan", "buy cheap"
    ]
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; SecurityResearch/1.0; "
            "+https://github.com/rocurun/gobscan)"
        )
    }
    try:
        r = requests.get(url, timeout=timeout, headers=headers,
                         allow_redirects=True)
        info["reachable"] = True
        info["status_code"] = r.status_code
        text_lower = r.text.lower()
        found = [kw for kw in all_keywords if kw in text_lower]
        info["keywords_found"] = found
        info["has_infection"] = len(found) > 0
    except Exception:
        pass
    return info


def generate_report_text(entries: list) -> str:
    """Genera texto de reporte para una o múltiples URLs."""
    if not entries:
        return ""

    dork     = entries[0].get("dork", "N/A")
    found_at = entries[0].get("found_at", "N/A")
    total    = len(entries)

    # Construir tabla de URLs
    url_lines = []
    for i, e in enumerate(entries, 1):
        url  = e.get("url", "N/A")
        kw   = ", ".join(e.get("keywords_found", [])) or "revisar manualmente"
        status = "INFECTADO" if e.get("has_infection") else "pendiente de verificar"
        url_lines.append(f"  {i:>2}. {url}")
        url_lines.append(f"      Estado   : {status}")
        url_lines.append(f"      Keywords : {kw}")
    urls_block = "\n".join(url_lines)

    # Dominios únicos afectados
    domains = sorted({urllib.parse.urlparse(e.get("url","")).netloc for e in entries if e.get("url")})
    domains_block = "\n".join(f"  - {d}" for d in domains)

    return f"""=== REPORTE DE SITIOS GUBERNAMENTALES COMPROMETIDOS ===
Fecha de detección : {found_at}
Dork utilizado     : {dork}
Total URLs halladas: {total}

URLs afectadas:
{urls_block}

Dominios únicos afectados:
{domains_block}

Descripción:
Los sitios gubernamentales indicados presentan síntomas de infección por spam
SEO blackhat. Las páginas de estos dominios aparecen en resultados de búsqueda
con contenido de casino/apuestas/farmacia/crypto no relacionado con la entidad
pública, indicando posible inyección de contenido, compromiso de CMS
(WordPress u otro) o redirecciones maliciosas.

Impacto:
- Daño reputacional a las entidades públicas afectadas
- Posible robo de datos a ciudadanos redirigidos
- Posicionamiento de sitios fraudulentos usando la autoridad del dominio .gob

Acción solicitada por cada dominio afectado:
- Revisar y limpiar el contenido inyectado
- Actualizar CMS y plugins a la última versión
- Revisar logs de acceso para determinar vector de entrada
- Forzar cambio de credenciales de administración
- Considerar auditoría de seguridad completa

Reportado vía GobScan — investigación de seguridad responsable
================================================================="""


def export_results(results: list[dict], fmt: str, output_file: str):
    """Exporta resultados a JSON o CSV."""
    if not results:
        print(f"  {Y}[!]{X} Sin resultados para exportar.")
        return
    if fmt == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    print(f"  {G}[✓]{X} Exportado a {B}{output_file}{X}")


def select_country() -> tuple[str, str]:
    print(f"\n  {C}Países disponibles:{X}")
    codes = list(GOV_DOMAINS.keys())
    for i, (code, domain) in enumerate(GOV_DOMAINS.items(), 1):
        print(f"    {B}{i:>2}.{X} {code}  →  {domain}")
    raw = input(f"\n  Código o número de país [{B}ec{X}]: ").strip().lower() or "ec"
    # Aceptar número o código
    if raw.isdigit() and 1 <= int(raw) <= len(codes):
        code = codes[int(raw) - 1]
    else:
        code = raw if raw in GOV_DOMAINS else "ec"
    return code, GOV_DOMAINS[code]


def select_preset() -> dict:
    print(f"\n  {C}Tipos de búsqueda:{X}")
    for key, p in DORK_PRESETS.items():
        print(f"    {B}{key}.{X} {p['name']:<30} {D}{p['desc']}{X}")

    choice = input(f"\n  Elige una opción [{B}1{X}]: ").strip() or "1"
    return DORK_PRESETS.get(choice, DORK_PRESETS["1"])


def ask_extra_words(preset: dict) -> list[str]:
    """Muestra las keywords del preset y permite añadir más."""
    # Presets con dork fijo no tienen keywords editables
    if "extra_dork" in preset:
        return []

    base = preset.get("keywords", [])
    print(f"\n  {C}Keywords base del preset:{X}")
    print(f"  {D}{', '.join(base)}{X}")
    print(f"\n  {Y}Puedes añadir palabras extra separadas por coma{X}")
    print(f"  {D}Ejemplos: tragamonedas, ruleta, bingo  /  sildenafil, tramadol{X}")
    raw = input(f"  Palabras extra (Enter para omitir): ").strip()

    if not raw:
        return []
    extras = [w.strip().lower() for w in raw.split(",") if w.strip()]
    if extras:
        print(f"  {G}[+]{X} Agregadas: {B}{', '.join(extras)}{X}")
    return extras


def collect_urls(dork: str) -> list[dict]:
    """Abre Google y pide al usuario ingresar las URLs encontradas."""
    search_url = open_and_search(dork)
    print(f"\n  {G}[✓]{X} Búsqueda abierta en el navegador")
    print(f"  {D}{search_url}{X}")
    print(f"""
  {B}Instrucciones:{X}
  {C}1.{X} Revisa los resultados en el navegador
  {C}2.{X} Copia las URLs de páginas gubernamentales infectadas
  {C}3.{X} Pégalas aquí una por una (Enter vacío para terminar)
    """)

    results = []
    while True:
        raw = input(f"  {C}URL #{len(results)+1}:{X} ").strip()
        if not raw:
            if not results:
                print(f"  {Y}[!]{X} No ingresaste ninguna URL.")
            break
        if not raw.startswith("http"):
            raw = "https://" + raw
        results.append({
            "url": raw,
            "dork": dork,
            "found_at": datetime.now().isoformat(),
            "status": "pending",
            "keywords_found": [],
            "notes": ""
        })
        print(f"  {G}  ✓ Guardada{X}")

    return results


def interactive_mode(preselected_country: str = ""):
    banner()
    print(f"{B}  ╔══ MODO INTERACTIVO ═══════════════════════════════╗{X}")

    # 1. País
    if preselected_country and preselected_country in GOV_DOMAINS:
        country_code = preselected_country
        domain_suffix = GOV_DOMAINS[country_code]
        print(f"  {G}[✓]{X} Dominio objetivo: {B}{domain_suffix}{X} (desde argumento)")
    else:
        country_code, domain_suffix = select_country()
        print(f"  {G}[✓]{X} Dominio objetivo: {B}{domain_suffix}{X}")

    # 2. Preset
    preset = select_preset()
    print(f"  {G}[✓]{X} Preset: {B}{preset['name']}{X}")

    # 3. Palabras extra
    extra_words = ask_extra_words(preset)

    # 4. Construir y mostrar dork
    dork = build_dork(domain_suffix, preset, extra_words)
    print(f"\n  {B}Dork final:{X}")
    print(f"  {G}{dork}{X}")

    input(f"\n  Presiona {B}Enter{X} para abrir la búsqueda en el navegador...")

    # 5. Recolectar URLs
    results = collect_urls(dork)

    if not results:
        print(f"\n  {Y}Sin URLs registradas. Sesión terminada.{X}\n")
        return

    # 6. Verificar URLs
    if REQUESTS_AVAILABLE:
        verify = input(
            f"\n  {C}¿Verificar URLs (confirmar infección activa)? [s/n]: {X}"
        ).strip().lower()
        if verify == "s":
            print(f"\n  {C}Verificando {len(results)} URLs...{X}")
            for r in results:
                print(f"  {D}→ {r['url']}{X}", end="  ", flush=True)
                info = verify_url(r["url"])
                r.update(info)
                if info["has_infection"]:
                    kw = ", ".join(info["keywords_found"])
                    print(f"{R}INFECTADO{X} [{kw}]")
                elif info["reachable"]:
                    print(f"{Y}activa, revisar manualmente{X}")
                else:
                    print(f"{D}no responde{X}")
    else:
        print(f"\n  {D}(instala 'requests' para verificación automática){X}")

    # 7. Mostrar resumen
    print(f"\n  {B}══ RESUMEN — {len(results)} URLs ══{X}")
    for i, r in enumerate(results, 1):
        icon = f"{R}●{X}" if r.get("has_infection") else f"{Y}○{X}"
        print(f"  {icon} {i}. {r['url']}")

    # 8. Generar reporte
    gen = input(f"\n  {C}¿Generar texto de reporte para CERT? [s/n]: {X}").strip().lower()
    if gen == "s":
        if len(results) == 1:
            to_report = results
        else:
            print(f"\n  {C}¿Qué URLs incluir en el reporte?{X}")
            print(f"    {B}0.{X} Todas ({len(results)} URLs)")
            for i, r in enumerate(results, 1):
                icon = f"{R}●{X}" if r.get("has_infection") else f"{Y}○{X}"
                print(f"    {B}{i}.{X} {icon} {r['url']}")
            raw = input(f"  Opción [{B}0 = todas{X}]: ").strip() or "0"
            if raw == "0":
                to_report = results
            else:
                # Permite selección múltiple: "1,3,4"
                selected_ids = []
                for part in raw.split(","):
                    part = part.strip()
                    if part.isdigit() and 1 <= int(part) <= len(results):
                        selected_ids.append(int(part) - 1)
                to_report = [results[i] for i in selected_ids] if selected_ids else results

        report_text = generate_report_text(to_report)
        print(f"\n{C}{'─'*65}{X}")
        print(report_text)
        print(f"{C}{'─'*65}{X}")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"reporte_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n  {G}[✓]{X} Reporte guardado en {B}{fname}{X} ({len(to_report)} URLs incluidas)")

    # 9. Exportar
    export = input(
        f"\n  {C}¿Exportar resultados? [json / csv / no]: {X}"
    ).strip().lower()
    if export in ("json", "csv"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_results(results, export, f"gobscan_{ts}.{export}")

    # 10. Canales de reporte
    print(f"\n  {B}══ CANALES DE REPORTE ══{X}")
    for name, url in REPORT_CHANNELS.items():
        print(f"  {G}►{X} {B}{name:<20}{X} {D}{url}{X}")

    print(f"\n  {G}[✓]{X} Sesión completada. Gracias por contribuir a la seguridad pública.\n")


def list_dorks(country: str = "ec"):
    banner()
    domain = GOV_DOMAINS.get(country, ".gob.ec")
    print(f"  {B}Dorks para {domain}:{X}\n")
    for key, p in DORK_PRESETS.items():
        dork = build_dork(domain, p, [])
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}&num=30"
        print(f"  {C}[{key}] {p['name']}{X}")
        print(f"  {dork}")
        print(f"  {D}{url}{X}\n")


def check_deps():
    banner()
    print(f"  {B}Estado de dependencias:{X}")
    print(f"  {'requests + bs4':<25} {G+'✓ instalado'+X if REQUESTS_AVAILABLE else R+'✗ falta'+X}")
    if not REQUESTS_AVAILABLE:
        print(f"\n  {Y}Para verificación automática de URLs:{X}")
        print(f"  {D}pip install requests beautifulsoup4{X}\n")


def main():
    parser = argparse.ArgumentParser(
        description="GobScan — Detección de sitios .gob infectados con spam blackhat SEO",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 gobscan.py                          # Modo interactivo (recomendado)
  python3 gobscan.py --list-dorks --country ec
  python3 gobscan.py --check-deps
        """
    )
    parser.add_argument(
        "--country",
        default=None,
        choices=GOV_DOMAINS.keys(),
        metavar="[" + ", ".join(GOV_DOMAINS.keys()) + "]",
        help="Código de país. Opciones: " + ", ".join(f"{k}={v}" for k, v in GOV_DOMAINS.items())
    )
    parser.add_argument("--list-dorks", action="store_true", help="Listar dorks para el país")
    parser.add_argument("--check-deps", action="store_true", help="Verificar dependencias")
    args = parser.parse_args()

    if args.check_deps:
        check_deps()
        return
    if args.list_dorks:
        list_dorks(args.country)
        return

    interactive_mode(preselected_country=args.country)


if __name__ == "__main__":
    main()
