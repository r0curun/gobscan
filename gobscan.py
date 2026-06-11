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


FALLBACK_KEYWORDS = [
    "casino", "poker", "slots", "apuestas", "ruleta", "tragamonedas",
    "blackjack", "baccarat", "bingo online",
    "viagra", "cialis", "pharmacy", "farmacia", "levitra", "sildenafil",
    "buy cheap pills", "online drugstore",
    "bitcoin", "crypto", "binance", "investment", "trading",
    "earn money online", "passive income", "forex",
    "prestamos", "credito rapido", "loan", "payday loan",
    "dinero rapido", "prestamo sin buro",
]

UA_RESEARCH = (
    "Mozilla/5.0 (compatible; SecurityResearch/1.0; "
    "+https://github.com/rocurun/gobscan)"
)
UA_GOOGLEBOT = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)"
)


def _extract_infection_signals(html: str, keywords: list[str]) -> dict:
    """
    Parsea el HTML con BeautifulSoup buscando keywords en:
      - texto visible normal
      - <title>
      - <meta name="keywords"> y <meta name="description">
      - links o elementos con display:none / visibility:hidden
      - comentarios HTML
    Devuelve {"keywords_found": [...], "hidden_spam": bool, "infected_title": bool}
    """
    soup = BeautifulSoup(html, "html.parser")
    found_in   = {}   # keyword → lista de ubicaciones donde se encontró

    def register(kw, location):
        found_in.setdefault(kw, [])
        if location not in found_in[kw]:
            found_in[kw].append(location)

    kw_lower = [k.lower() for k in keywords]

    # 1. <title>
    title_tag = soup.find("title")
    title_text = title_tag.get_text(separator=" ").lower() if title_tag else ""
    for kw in kw_lower:
        if kw in title_text:
            register(kw, "title")

    # 2. <meta keywords> y <meta description>
    for meta in soup.find_all("meta"):
        content = (meta.get("content") or "").lower()
        name    = (meta.get("name")    or "").lower()
        if name in ("keywords", "description"):
            for kw in kw_lower:
                if kw in content:
                    register(kw, f"meta:{name}")

    # 3. Elementos ocultos (display:none / visibility:hidden)
    hidden_spam = False
    for tag in soup.find_all(style=True):
        style = tag.get("style", "").replace(" ", "").lower()
        if "display:none" in style or "visibility:hidden" in style:
            tag_text = tag.get_text(separator=" ").lower()
            for kw in kw_lower:
                if kw in tag_text:
                    register(kw, "hidden_element")
                    hidden_spam = True

    # 4. Comentarios HTML
    from bs4 import Comment
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment_lower = comment.lower()
        for kw in kw_lower:
            if kw in comment_lower:
                register(kw, "html_comment")

    # 5. Texto visible general (captura lo que no cayó en categorías anteriores)
    body_text = soup.get_text(separator=" ").lower()
    for kw in kw_lower:
        if kw in body_text:
            register(kw, "body_text")

    all_found   = list(found_in.keys())
    title_hit   = any("title" in locs for locs in found_in.values())

    return {
        "keywords_found":  all_found,
        "keywords_detail": found_in,      # dónde exactamente se encontró cada kw
        "hidden_spam":     hidden_spam,
        "infected_title":  title_hit,
    }


def verify_url(url: str, timeout: int = 8,
               preset_keywords: list[str] | None = None) -> dict:
    """
    Verifica si la URL sigue infectada con blackhat SEO.

    Mejoras respecto a la versión anterior:
      - Usa las keywords del preset activo (no lista hardcodeada)
      - Parsea <title>, <meta>, elementos ocultos y comentarios HTML
      - Detecta cloaking básico comparando respuesta normal vs Googlebot
      - Detecta redirects que sacan al usuario del dominio .gob
    """
    info = {
        "reachable":       False,
        "status_code":     None,
        "has_infection":   False,
        "keywords_found":  [],
        "keywords_detail": {},
        "hidden_spam":     False,
        "infected_title":  False,
        "cloaking":        False,
        "redirect_hijack": False,
        "final_url":       url,
    }
    if not REQUESTS_AVAILABLE:
        return info

    keywords = preset_keywords if preset_keywords else FALLBACK_KEYWORDS

    def fetch(ua: str) -> requests.Response | None:
        try:
            return requests.get(
                url, timeout=timeout,
                headers={"User-Agent": ua},
                allow_redirects=True,
            )
        except Exception:
            return None

    # ── Request normal ──────────────────────────────────────────────────────
    resp_normal = fetch(UA_RESEARCH)
    if resp_normal is None:
        return info   # no responde

    info["reachable"]   = True
    info["status_code"] = resp_normal.status_code
    info["final_url"]   = resp_normal.url

    # ── Redirect hijack: ¿el dominio final ya no es .gob? ──────────────────
    from urllib.parse import urlparse
    original_netloc = urlparse(url).netloc
    final_netloc    = urlparse(resp_normal.url).netloc
    if final_netloc and final_netloc != original_netloc:
        # Si además el dominio final no es gubernamental → redirect sospechoso
        gov_tlds = (".gob.", ".gov.", ".gub.")
        if not any(t in final_netloc for t in gov_tlds):
            info["redirect_hijack"] = True

    # ── Parseo profundo de la respuesta normal ──────────────────────────────
    signals_normal = _extract_infection_signals(resp_normal.text, keywords)
    info.update(signals_normal)
    info["has_infection"] = (
        bool(signals_normal["keywords_found"])
        or info["redirect_hijack"]
    )

    # ── Detección de cloaking: request con UA de Googlebot ──────────────────
    # Solo hacemos el segundo request si el primero no encontró nada
    # (si ya encontró infección no hace falta; el cloaking es cuando
    #  Googlebot ve spam pero el usuario normal NO lo ve)
    if not signals_normal["keywords_found"]:
        resp_bot = fetch(UA_GOOGLEBOT)
        if resp_bot is not None:
            signals_bot = _extract_infection_signals(resp_bot.text, keywords)
            if signals_bot["keywords_found"]:
                # Googlebot ve spam pero UA normal no → cloaking clásico
                info["cloaking"]       = True
                info["has_infection"]  = True
                info["keywords_found"] = signals_bot["keywords_found"]
                info["keywords_detail"]= signals_bot["keywords_detail"]
                info["hidden_spam"]    = signals_bot["hidden_spam"]
                info["infected_title"] = signals_bot["infected_title"]

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
            # Construir lista de keywords activas para este preset
            active_kw = preset.get("keywords", []) + extra_words or FALLBACK_KEYWORDS

            print(f"\n  {C}Verificando {len(results)} URLs...{X}")
            for r in results:
                print(f"  {D}→ {r['url']}{X}", end="  ", flush=True)
                info = verify_url(r["url"], preset_keywords=active_kw)
                r.update(info)
                if info["has_infection"]:
                    kw = ", ".join(info["keywords_found"])
                    tags = []
                    if info.get("cloaking"):        tags.append(f"{Y}CLOAKING{X}")
                    if info.get("redirect_hijack"): tags.append(f"{Y}REDIRECT{X}")
                    if info.get("hidden_spam"):     tags.append(f"{Y}OCULTO{X}")
                    if info.get("infected_title"):  tags.append(f"{Y}TÍTULO{X}")
                    tag_str = " ".join(tags)
                    print(f"{R}INFECTADO{X} {tag_str} [{kw}]")
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
