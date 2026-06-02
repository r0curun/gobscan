# 🛡️ GobScan

Herramienta CLI en Python para detectar y reportar sitios gubernamentales (.gob) infectados con spam SEO blackhat.

Desarrollada para facilitar el reporte responsable de vulnerabilidades en infraestructura pública de América Latina.

> Creada y mantenida por [@rocurun](https://twitter.com/rocurun)

---

## ¿Qué hace?

Los atacantes inyectan contenido de casinos, farmacias ilegales, crypto y préstamos en sitios `.gob.ec`, `.gob.pe`, `.gov.co`, etc., aprovechando la autoridad del dominio para posicionar sus sitios fraudulentos en Google.

GobScan automatiza la búsqueda de estos sitios usando Google Dorks y genera reportes listos para enviar a los CERTs nacionales.

```
País → Preset de dork → Palabras extra → Google → Pegar URLs → Verificar → Reporte
```

---

## Instalación

```bash
git clone https://github.com/rocurun/gobscan.git
cd gobscan
pip install requests beautifulsoup4
```

> `requests` y `beautifulsoup4` son opcionales — solo se usan para verificar si las URLs siguen infectadas. La herramienta funciona sin ellas.

---

## Uso

### Modo interactivo (recomendado)
```bash
python3 gobscan.py
```

### Ver todos los dorks para un país
```bash
python3 gobscan.py --list-dorks --country ec
python3 gobscan.py --list-dorks --country pe
```

### Verificar dependencias
```bash
python3 gobscan.py --check-deps
```

---

## Países soportados

| Código | Dominio     |
|--------|-------------|
| ec     | .gob.ec     |
| pe     | .gob.pe     |
| co     | .gov.co     |
| mx     | .gob.mx     |
| ar     | .gob.ar     |
| cl     | .gob.cl     |
| bo     | .gob.bo     |
| ve     | .gob.ve     |
| py     | .gov.py     |
| uy     | .gub.uy     |
| br     | .gov.br     |

---

## Presets de dorks

| # | Nombre                    | Descripción |
|---|---------------------------|-------------|
| 1 | Casino / Apuestas         | Spam de casinos y apuestas (el más común en .gob.ec) |
| 2 | Farmacia / Pharma         | Inyección de spam farmacéutico |
| 3 | Crypto / Inversiones      | Spam de criptomonedas e inversiones fraudulentas |
| 4 | Préstamos / Finanzas      | Spam de préstamos y servicios financieros dudosos |
| 5 | Archivos PHP sospechosos  | Posibles webshells subidos al servidor |
| 6 | Directorios expuestos     | Directorios públicos con archivos sensibles |
| 7 | WordPress mal configurado | Endpoints de usuario expuestos |
| 8 | Redirecciones sospechosas | Parámetros usados para phishing |
| 9 | Títulos comprometidos     | Páginas cuyo título fue reemplazado por spam |

Cada preset de tipo keyword (1-4 y 9) permite **agregar palabras extra** adaptadas a tu región:
```
Keywords base: casino, poker, slots, apuestas, ruleta...
Tus palabras : tragamonedas, bingo, loteria
→ site:.gob.ec intext:"casino" OR "poker" OR ... OR "tragamonedas"
```

---

## Flujo completo

```
1. Elegir país
2. Elegir preset
3. Agregar palabras extra (opcional)
4. GobScan abre Google con el dork listo
5. Copias las URLs infectadas que encuentras
6. GobScan verifica si siguen activas (opcional)
7. Genera reporte para enviar al CERT
8. Exporta resultados en JSON o CSV
```

---

## Canales de reporte

| CERT | Enlace |
|------|--------|
| CERT-EC | https://www.ecucert.gob.ec/reportar |
| CERT LACNIC | https://lacnic.net/4983/2/lacnic/cert-lacnic |
| Google Safe Browsing | https://safebrowsing.google.com/safebrowsing/report_phish/ |
| URLhaus | https://urlhaus.abuse.ch/ |

---

## Sin APIs, sin claves, sin registro

GobScan no requiere ninguna API key ni cuenta en servicios externos. Solo Python y tu navegador.

---

## Uso ético

Esta herramienta es exclusivamente para **investigación de seguridad responsable** y **reporte de vulnerabilidades**. Úsala solo para reportar sitios comprometidos a las autoridades correspondientes.

---
## Notas de uso

### Google muestra resultados vacíos al abrir
Es normal. Google a veces trata la URL generada con cautela la primera vez.
**Solución:** En el navegador haz clic en "Herramientas → Última hora" 
y luego selecciona cualquier rango de fecha. Esto fuerza a Google a 
reejecutar la búsqueda y mostrar los resultados correctamente.

No afecta el funcionamiento de la herramienta.

## Licencia

MIT — libre para usar, modificar y distribuir.
