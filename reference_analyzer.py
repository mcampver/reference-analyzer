"""
Analizador de Referencias en Artículos Científicos
Proyecto para Modelos Matemáticos Aplicados, C3
Facultad de Matemática y Computación, UH
"""

import re
import pdfplumber
from collections import defaultdict, Counter
from datetime import datetime
import json
from typing import List, Dict, Tuple, Set
import argparse
from pathlib import Path

class ReferenceAnalyzer:
    def __init__(self):
        # Patrones para detectar diferentes formatos de citas
        self.citation_patterns = [
            # Formato (Autor, Año)
            r'\(([A-Za-z\s&]+,?\s+\d{4}[a-z]?)\)',
            # Formato [1], [2], [1-3], [1,2,3]
            r'\[(\d+(?:[-,]\d+)*)\]',
            # Formato Autor (Año)
            r'\[([A-Za-z]+\d{4}[a-z]?(?:,[A-Za-z]+\d{4}[a-z]?)*)\]',
            # Formato superíndice ¹²³
            r'([¹²³⁴⁵⁶⁷⁸⁹⁰]+)',
        ]
        
        # Patrones para extraer años de las referencias
        self.year_patterns = [
            r'\b(19|20)\d{2}\b',  # Años de 1900-2099
            r'\((\d{4})\)',       # Años entre paréntesis
        ]
        
        # Palabras clave que indican secciones de referencias
        self.reference_section_keywords = [
            'references', 'bibliography', 'bibliografía', 'referencias',
            'works cited', 'literature cited', 'citations'
        ]

    def extract_text_from_pdf(self, pdf_path: str) -> str:
        """Extrae todo el texto del PDF"""
        try:
            with pdfplumber.open(pdf_path) as pdf:
                text = ""
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
                return text
        except Exception as e:
            raise Exception(f"Error al leer el PDF: {str(e)}")

    def split_document_sections(self, text: str) -> Tuple[str, str]:
        """Separa el documento en cuerpo principal y sección de referencias"""
        text_lower = text.lower()
        
        # Buscar el inicio de la sección de referencias
        ref_start = -1
        for keyword in self.reference_section_keywords:
            pattern = rf'\b{keyword}\b'
            matches = list(re.finditer(pattern, text_lower))
            if matches:
                # Tomar la última ocurrencia (más probable que sea la bibliografía)
                ref_start = matches[-1].start()
                break
        
        if ref_start == -1:
            # Si no encontramos sección de referencias, asumir que las últimas páginas son referencias
            # Tomamos aproximadamente el último 20% del texto
            ref_start = int(len(text) * 0.8)
        
        body_text = text[:ref_start]
        references_text = text[ref_start:]
        
        return body_text, references_text

    def extract_citations_from_body(self, body_text: str) -> Set[str]:
        """Extrae todas las citas del cuerpo del documento"""
        citations = set()
        
        # Buscar citas numéricas [1], [2], [1, 2], etc.
        numeric_citations = re.findall(r'\[(\d+(?:,\s*\d+)*)\]', body_text)
        for citation in numeric_citations:
            # Separar citas múltiples como [1, 2] en citas individuales
            for num in re.findall(r'\d+', citation):
                citations.add(num.strip())
        
        # Buscar otros formatos de citas
        for pattern in self.citation_patterns:
            if '[' not in pattern:  # Evitar duplicados con la búsqueda numérica arriba
                matches = re.findall(pattern, body_text, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]  # Para grupos de captura
                    citations.add(self.clean_citation(match))
        
        return citations

    def clean_citation(self, citation: str) -> str:
        """Limpia y normaliza una cita"""
        # Remover espacios extra y caracteres especiales
        citation = re.sub(r'\s+', ' ', citation.strip())
        # Convertir a minúsculas para comparación
        return citation.lower()

    def extract_references_from_bibliography(self, references_text: str) -> List[Dict]:
        """Extrae las referencias de la sección de bibliografía"""
        references = []
        
        # Dividir por líneas y filtrar líneas vacías
        lines = [line.strip() for line in references_text.split('\n') if line.strip()]
        
        # Filtrar líneas que solo contienen encabezados de sección como "Referencias" o "References"
        lines = [line for line in lines if not re.match(r'^(Referencias|References|Bibliography|Bibliografía)$', line, re.IGNORECASE)]
        
        current_ref = ""
        for line in lines:
            # Si la línea parece ser el inicio de una nueva referencia
            if self.is_new_reference(line):
                if current_ref:
                    ref_info = self.parse_reference(current_ref)
                    if ref_info:
                        references.append(ref_info)
                current_ref = line
            else:
                # Continuar con la referencia actual
                current_ref += " " + line
        
        # Procesar la última referencia
        if current_ref:
            ref_info = self.parse_reference(current_ref)
            if ref_info:
                references.append(ref_info)
        
        return references

    def is_new_reference(self, line: str) -> bool:
        """Determina si una línea es el inicio de una nueva referencia"""
        # Buscar patrones comunes de inicio de referencia
        patterns = [
            r'^\[\d+\]',  # [1], [2], etc.
            r'^\d+\.',    # 1., 2., etc.
            r'^[A-Z][a-z]+,',  # Apellido,
            r'^[A-Z]\.',  # Inicial de nombre
            r'\\bibitem\{.*?\}', # \bibitem{key}
            r'^\\bibitem',      # \bibitem
            r'^\[[\w\d]+\]',    # [Ng2012], [Smith2020], etc.
        ]
        
        for pattern in patterns:
            if re.match(pattern, line):
                return True
        
        return False

    def parse_reference(self, ref_text: str) -> Dict:
        """Extrae información de una referencia individual"""
        ref_info = {
            'text': ref_text,
            'year': self.extract_year_from_reference(ref_text),
            'authors': self.extract_authors_from_reference(ref_text)
        }
        return ref_info

    def extract_year_from_reference(self, ref_text: str) -> int:
        """Extrae el año de una referencia"""
        # Buscar patrones comunes de años
        year_patterns = [
            r'\b(19|20)\d{2}\b',       # Años básicos: 1900-2099
            r'\b(19|20)\d{2}[.,]',     # Años con puntuación: 2020.
            r'(19|20)\d{2}(?=\s|$)',   # Años seguidos de espacio o fin
            r'[,\s](19|20)\d{2}',      # Años con separador antes
            r'\((\d{4})\)',            # Años entre paréntesis
            r'(\d{4})\.?\s*$'          # Años al final de la línea
        ]
        
        for pattern in year_patterns:
            matches = re.findall(pattern, ref_text)
            if matches:
                for match in matches:
                    year_str = match if isinstance(match, str) else match
                    # Limpiar el año (eliminar caracteres no numéricos)
                    year_str = re.sub(r'\D', '', year_str)
                    try:
                        year = int(year_str)
                        if 1900 <= year <= datetime.now().year + 5:  # Permitir hasta 5 años en el futuro
                            return year
                    except (ValueError, TypeError):
                        continue
        
        # Búsqueda más agresiva como último recurso
        all_numbers = re.findall(r'\d{4}', ref_text)
        for num in all_numbers:
            try:
                year = int(num)
                if 1900 <= year <= datetime.now().year + 5:
                    return year
            except ValueError:
                continue
        
        return None

    def extract_authors_from_reference(self, ref_text: str) -> List[str]:
        """Extrae autores de una referencia (implementación básica)"""
        # Esta es una implementación simple, se puede mejorar
        # Buscar patrones de nombres al inicio de la referencia
        author_pattern = r'^([A-Z][a-z]+(?:,\s*[A-Z]\.)*(?:\s*&\s*[A-Z][a-z]+(?:,\s*[A-Z]\.)*)*)'
        match = re.match(author_pattern, ref_text)
        if match:
            authors_str = match.group(1)
            # Dividir por & o 'and'
            authors = re.split(r'\s*&\s*|\s+and\s+', authors_str)
            return [author.strip() for author in authors]
        return []

    def analyze_time_distribution(self, references: List[Dict]) -> Dict:
        """Analiza la distribución temporal de las referencias"""
        current_year = datetime.now().year
        time_periods = {
            'last_5_years': 0,
            'last_10_years': 0,
            'last_15_years': 0,
            'older': 0,
            'no_year': 0
        }
        
        year_distribution = Counter()
        
        for ref in references:
            year = ref.get('year')
            
            if year:
                year_distribution[year] += 1
                
                years_ago = current_year - year
                
                if years_ago <= 5:
                    time_periods['last_5_years'] += 1
                elif years_ago <= 10:
                    time_periods['last_10_years'] += 1
                elif years_ago <= 15:
                    time_periods['last_15_years'] += 1
                else:
                    time_periods['older'] += 1
            else:
                time_periods['no_year'] += 1
        
        return {
            'time_periods': time_periods,
            'year_distribution': dict(year_distribution),
            'total_references': len(references)
        }

    def find_uncited_references(self, citations: Set[str], references: List[Dict]) -> List[Dict]:
        """Encuentra referencias que no están citadas en el texto"""
        uncited = []
        
        for ref in references:
            ref_text = ref['text'].lower()
            is_cited = False
            
            # Para referencias con formato [1], [2], etc.
            ref_number_match = re.match(r'^\[(\d+)\]', ref_text)
            if ref_number_match:
                ref_number = ref_number_match.group(1)
                if ref_number in citations:
                    is_cited = True
                    continue
            
            # Buscar si alguna parte de la referencia coincide con las citas
            for citation in citations:
                if self.references_match(citation, ref_text, ref.get('year')):
                    is_cited = True
                    break
            
            if not is_cited:
                uncited.append(ref)
        
        return uncited

    def references_match(self, citation: str, ref_text: str, ref_year: int) -> bool:
        """Determina si una cita coincide con una referencia"""
        # Para citas numéricas como "1", "2", etc.
        if citation.isdigit():
            # Buscar si la referencia comienza con [número]
            match = re.match(r'^\[' + citation + r'\]', ref_text)
            if match:
                return True
        
        # Si la cita contiene el año de la referencia
        if ref_year and str(ref_year) in citation:
            return True
        
        # Buscar coincidencias en nombres de autores
        words_in_citation = citation.split()
        words_in_ref = ref_text.split()
        
        common_words = set(words_in_citation) & set(words_in_ref)
        
        # Si hay suficientes palabras en común (heurística simple)
        if len(common_words) >= 2:
            return True
        
        return False

    def generate_report(self, analysis_results: Dict) -> str:
        """Genera un reporte completo del análisis"""
        report = []
        report.append("=" * 60)
        report.append("ANÁLISIS DE REFERENCIAS EN ARTÍCULO CIENTÍFICO")
        report.append("=" * 60)
        report.append("")  # Corregir aquí con una cadena vacía
        
        # Estadísticas generales
        report.append("ESTADÍSTICAS GENERALES:")
        report.append(f"- Total de referencias encontradas: {analysis_results['total_references']}")
        report.append(f"- Total de citas en el texto: {analysis_results['total_citations']}")
        report.append(f"- Referencias no citadas: {len(analysis_results['uncited_references'])}")
        report.append("")  # Corregir aquí
        
        # Distribución temporal
        time_dist = analysis_results['time_distribution']
        report.append("DISTRIBUCIÓN TEMPORAL DE REFERENCIAS:")
        report.append(f"- Últimos 5 años: {time_dist['time_periods']['last_5_years']}")
        report.append(f"- Últimos 10 años: {time_dist['time_periods']['last_10_years']}")
        report.append(f"- Últimos 15 años: {time_dist['time_periods']['last_15_years']}")
        report.append(f"- Más antiguas: {time_dist['time_periods']['older']}")
        report.append(f"- Sin año identificado: {time_dist['time_periods']['no_year']}")
        report.append("")
        
        # Referencias no citadas
        if analysis_results['uncited_references']:
            report.append("REFERENCIAS NO CITADAS EN EL TEXTO:")
            for i, ref in enumerate(analysis_results['uncited_references'], 1):
                report.append(f"{i}. {ref['text'][:100]}...")
            report.append('')
        
        # Distribución por años (top 10)
        if time_dist['year_distribution']:
            sorted_years = sorted(time_dist['year_distribution'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]
            report.append("AÑOS CON MÁS REFERENCIAS (Top 10):")
            for year, count in sorted_years:
                report.append(f"- {year}: {count} referencias")
            report.append('')
        
        return "\n".join(report)

    def analyze_document(self, pdf_path: str) -> Dict:
        """Función principal que realiza el análisis completo"""
        print(f"Analizando documento: {pdf_path}")
        
        # Extraer texto del PDF
        print("Extrayendo texto del PDF...")
        full_text = self.extract_text_from_pdf(pdf_path)
        
        # Separar cuerpo y referencias
        print("Separando secciones del documento...")
        body_text, references_text = self.split_document_sections(full_text)
        
        # Extraer citas del cuerpo
        print("Extrayendo citas del texto...")
        citations = self.extract_citations_from_body(body_text)
        
        # Extraer referencias de la bibliografía
        print("Extrayendo referencias de la bibliografía...")
        references = self.extract_references_from_bibliography(references_text)
        
        # Analizar distribución temporal
        print("Analizando distribución temporal...")
        time_distribution = self.analyze_time_distribution(references)
        
        # Encontrar referencias no citadas
        print("Identificando referencias no citadas...")
        uncited_references = self.find_uncited_references(citations, references)
        
        results = {
            'total_references': len(references),
            'total_citations': len(citations),
            'citations': list(citations),
            'references': references,
            'uncited_references': uncited_references,
            'time_distribution': time_distribution
        }
        
        return results


def main():
    parser = argparse.ArgumentParser(description='Analizador de Referencias en Artículos Científicos')
    parser.add_argument('pdf_file', nargs='?', help='Ruta al archivo PDF a analizar')
    parser.add_argument('--output', '-o', help='Archivo de salida para el reporte')
    parser.add_argument('--json', action='store_true', help='Generar salida en formato JSON')
    parser.add_argument('--batch', '-b', action='store_true', help='Procesar todos los PDFs en un directorio')
    
    args = parser.parse_args()
    
    # Determinar qué archivos procesar
    pdf_files = []
    
    # Si no se especifica un archivo o directorio, usar la carpeta examples
    if not args.pdf_file:
        examples_dir = Path('examples')
        if not examples_dir.exists():
            examples_dir = Path(Path(__file__).parent / 'examples')
        
        if not examples_dir.exists():
            print(f"Error: No se encontró la carpeta de ejemplos. Crear una carpeta 'examples' con archivos PDF.")
            return
        
        pdf_files = list(examples_dir.glob('*.pdf'))
        if not pdf_files:
            print(f"Error: No se encontraron archivos PDF en {examples_dir}")
            return
        
        print(f"Procesando {len(pdf_files)} archivos PDF de la carpeta {examples_dir}")
    
    # Si se especificó un archivo concreto
    elif Path(args.pdf_file).is_file():
        if not args.pdf_file.lower().endswith('.pdf'):
            print("Error: El archivo especificado no es un PDF.")
            return
        
        pdf_files = [Path(args.pdf_file)]
    
    # Si se especificó un directorio y --batch
    elif Path(args.pdf_file).is_dir() and args.batch:
        pdf_files = list(Path(args.pdf_file).glob('*.pdf'))
        if not pdf_files:
            print(f"Error: No se encontraron archivos PDF en {args.pdf_file}")
            return
        
        print(f"Procesando {len(pdf_files)} archivos PDF de la carpeta {args.pdf_file}")
    
    # Si el archivo especificado no existe
    else:
        print(f"Error: El archivo o directorio {args.pdf_file} no existe.")
        return
    
    analyzer = ReferenceAnalyzer()
    
    # Procesar cada archivo PDF
    for pdf_file in pdf_files:
        print(f"\nProcesando: {pdf_file}")
        
        try:
            results = analyzer.analyze_document(str(pdf_file))
            
            # Determinar nombre de salida basado en archivo de entrada
            output_file = None
            if args.output:
                if len(pdf_files) == 1:
                    output_file = args.output
                else:
                    # Cuando hay múltiples archivos, crear un nombre para cada uno
                    base_name = Path(args.output).stem
                    ext = Path(args.output).suffix
                    output_file = f"{base_name}_{pdf_file.stem}{ext}"
            else:
                # Si no se especificó nombre de salida, usar nombre del PDF
                output_file = pdf_file.with_suffix('.txt' if not args.json else '.json')
            
            if args.json:
                # Salida en JSON
                output = json.dumps(results, indent=2, ensure_ascii=False, default=str)
            else:
                # Salida en texto
                output = analyzer.generate_report(results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Reporte guardado en: {output_file}")
                
        except Exception as e:
            print(f"Error durante el análisis de {pdf_file}: {str(e)}")
if __name__ == "__main__":
    main()