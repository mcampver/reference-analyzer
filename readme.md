# Analizador de Referencias en Artículos Científicos

Una herramienta para analizar la sección de referencias en artículos científicos en formato PDF.

## Características

- Extrae citas del cuerpo del texto
- Identifica referencias bibliográficas
- Analiza la distribución temporal de las referencias
- Detecta referencias no citadas en el documento
- Genera informes detallados de las referencias

## Requisitos

- Python 3.6+
- Dependencias: pdfplumber, argparse

## Instalación

```bash
pip install -r requirements.txt

# Analizar un único PDF
python reference_analyzer.py ruta/al/archivo.pdf

# Analizar todos los PDFs en un directorio
python reference_analyzer.py ruta/al/directorio --batch

# Generar salida en formato JSON
python reference_analyzer.py archivo.pdf --json

# Especificar archivo de salida
python reference_analyzer.py archivo.pdf -o reporte.txt

# Sin argumentos (procesa PDFs en carpeta examples/)
python reference_analyzer.py