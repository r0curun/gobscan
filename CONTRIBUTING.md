# Contribuir a GobScan

¡Gracias por tu interés en mejorar GobScan! Este proyecto vive de la comunidad de seguridad de América Latina. Aquí te explicamos cómo colaborar.

---

## ¿Cómo puedo contribuir?

- Agregar nuevos dorks o palabras clave
- Agregar soporte para más países
- Mejorar el código existente
- Reportar bugs
- Mejorar la documentación

---

## Flujo de contribución (Fork + Pull Request)

### Paso 1 — Haz un Fork
En la página del repo haz clic en el botón **Fork** (arriba a la derecha).
Esto crea una copia del proyecto en tu cuenta de GitHub.

### Paso 2 — Clona tu fork
```bash
git clone https://github.com/TU-USUARIO/gobscan.git
cd gobscan
```

### Paso 3 — Crea una rama para tu mejora
```bash
git checkout -b feature/nombre-de-tu-mejora
```
Ejemplos de nombres de rama:
```
feature/nuevos-dorks-casino
fix/reporte-multiples-urls
feature/soporte-pais-cr
```

### Paso 4 — Haz tus cambios y confirma
```bash
git add .
git commit -m "Descripción clara de lo que cambiaste"
```

### Paso 5 — Sube tu rama a GitHub
```bash
git push origin feature/nombre-de-tu-mejora
```

### Paso 6 — Abre un Pull Request
1. Ve a https://github.com/r0curun/gobscan
2. Verás un botón **Compare & pull request**
3. Describe qué cambiaste y por qué
4. Clic en **Create pull request**

El mantenedor revisará tu código, puede pedir ajustes, y si todo está bien lo aprobará con **Merge**.

---

## Guía para agregar nuevos dorks

Los dorks están en el diccionario `DORK_PRESETS` dentro de `gobscan.py`.

Para agregar un nuevo preset sigue esta estructura:

```python
"10": {
    "name": "Nombre descriptivo",
    "keywords": ["palabra1", "palabra2", "palabra3"],
    "desc": "Descripción corta de qué detecta este preset"
},
```

Si es un dork con sintaxis fija (sin keywords variables):

```python
"10": {
    "name": "Nombre descriptivo",
    "keywords": [],
    "extra_dork": 'intitle:"index of" "config.php"',
    "desc": "Descripción corta de qué detecta este preset"
},
```

---

## Guía para agregar nuevos países

Los países están en el diccionario `GOV_DOMAINS`:

```python
GOV_DOMAINS = {
    "ec":  ".gob.ec",
    "pe":  ".gob.pe",
    # agregar aquí
    "cr":  ".go.cr",   # ejemplo: Costa Rica
    "gt":  ".gob.gt",  # ejemplo: Guatemala
}
```

---

## Estilo de código

- Python 3.10+
- Sin dependencias externas obligatorias (todo debe funcionar con stdlib)
- `requests` y `beautifulsoup4` solo para funciones opcionales
- Comentarios en español
- Mensajes de la CLI en español

---

## Reportar un bug

Abre un **Issue** en https://github.com/r0curun/gobscan/issues con:

- Descripción del problema
- Pasos para reproducirlo
- Sistema operativo y versión de Python (`python3 --version`)
- Output del error si aplica

---

## Código de conducta

Este proyecto es para **investigación de seguridad responsable**. No se aceptarán contribuciones que:

- Conviertan la herramienta en un scanner activo sin consentimiento
- Automaticen ataques en lugar de reportes
- Eliminen las advertencias de uso ético

---

Mantenido por [@r0curun](https://twitter.com/rocurun)
