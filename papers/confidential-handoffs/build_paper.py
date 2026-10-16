"""Build paper.pdf from paper.md with ReportLab and embedded Times/Arial TrueType fonts.

Usage: python build_paper.py --source . --output paper.pdf [--fonts DIR]
Requires reportlab and pymupdf; fonts are read from --fonts (default C:/Windows/Fonts).
"""
from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

import argparse
from functools import partial
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--fonts', type=Path, default=Path('C:/Windows/Fonts'))
a = p.parse_args()
ROOT = a.source
for name, filename in [('SubmissionSerif', 'times.ttf'), ('SubmissionBold', 'timesbd.ttf'), ('SubmissionSans', 'arial.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(a.fonts / filename)))
pdfmetrics.registerFontFamily('SubmissionSerif', normal='SubmissionSerif', bold='SubmissionBold', italic='SubmissionSerif', boldItalic='SubmissionBold')
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='PaperTitle', fontName='SubmissionBold', fontSize=23, leading=27,
                          spaceAfter=12, textColor=colors.HexColor('#15334b')))
styles.add(ParagraphStyle(name='PaperHeading', fontName='SubmissionBold', fontSize=13, leading=17,
                          spaceBefore=13, spaceAfter=6, keepWithNext=True))
styles.add(ParagraphStyle(name='PaperBody', fontName='SubmissionSerif', fontSize=10.6, leading=14.3,
                          spaceAfter=6, alignment=TA_LEFT, splitLongWords=True))
styles.add(ParagraphStyle(name='PaperCell', fontName='SubmissionSerif', fontSize=8.7, leading=11,
                          spaceAfter=2, splitLongWords=True))
styles.add(ParagraphStyle(name='PaperBullet', parent=styles['PaperBody'], leftIndent=11,
                          firstLineIndent=-7))


def markup(text):
    text = escape(text)
    text = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', r'<link href="\2" color="#174d76">\1</link>', text)
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    text = text.replace(chr(96), '')
    return text


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor('#ccd5dc'))
    canvas.line(0.8*inch, 0.57*inch, 7.7*inch, 0.57*inch)
    canvas.setFont('SubmissionSans', 8)
    canvas.setFillColor(colors.HexColor('#52616e'))
    canvas.drawString(0.8*inch, 0.4*inch, 'OPAQUE Systems | Technical report, version 3 | Software evidence; hardware acceptance is future work')
    canvas.drawRightString(7.7*inch, 0.4*inch, str(doc.page))
    canvas.restoreState()


def build():
    story = []
    lines = (ROOT/'paper.md').read_text(encoding='utf-8-sig').splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line.startswith('|'):
            rows = []
            cells_header = [v.strip() for v in lines[i].strip().strip('|').split('|')]
            while i < len(lines) and lines[i].strip().startswith('|'):
                cells = [v.strip() for v in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[-: ]+', c) for c in cells):
                    rows.append([Paragraph(markup(c), styles['PaperCell']) for c in cells])
                i += 1
            widths = {2: [2.3*inch, 4.6*inch], 3: [1.82*inch, 1.72*inch, 3.36*inch]}[len(rows[0])]
            if cells_header[0] == 'Change under test':
                widths = [1.75*inch, 2.45*inch, 2.7*inch]
            table = Table(rows, colWidths=widths, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e5edf3')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 6), ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 5), ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LINEBELOW', (0,0), (-1,0), 0.7, colors.HexColor('#9aaebc')),
                ('LINEBELOW', (0,1), (-1,-1), 0.25, colors.HexColor('#d9e0e5')),
            ]))
            story.extend([table, Spacer(1, 9)])
            continue
        if line.startswith('# '):
            story.append(Paragraph(markup(line[2:]), styles['PaperTitle']))
        elif line.startswith(('## ', '### ', '#### ')):
            story.append(Paragraph(markup(line.lstrip('#').strip()), styles['PaperHeading']))
        elif re.match(r'^\d+\. ', line):
            story.append(Paragraph(markup(line), styles['PaperBody']))
        elif line.startswith('- '):
            story.append(Paragraph('&#8226; '+markup(line[2:]), styles['PaperBullet']))
        else:
            paragraph = [line]
            while i+1 < len(lines) and lines[i+1].strip() and not lines[i+1].startswith(('#','|','- ')) and not re.match(r'^\d+\. ', lines[i+1]):
                i += 1
                paragraph.append(lines[i].strip())
            story.append(Paragraph(markup(' '.join(paragraph)), styles['PaperBody']))
        i += 1
    doc = SimpleDocTemplate(str(a.output), pagesize=(8.5*inch, 11*inch),
                            rightMargin=0.8*inch, leftMargin=0.8*inch, topMargin=0.65*inch,
                            bottomMargin=0.8*inch, title='Confidentiality Across Agent Handoffs',
                            author='Imran Siddique', pageCompression=1, invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer, canvasmaker=partial(Canvas, initialFontName='SubmissionSans'))


if __name__ == '__main__':
    build()
    # Remove ReportLab's unused base-font resource; retain embedded font streams.
    import pymupdf
    with pymupdf.open(a.output) as pdf:
        for page in pdf:
            page.clean_contents()
        cleaned = pdf.tobytes(garbage=4, deflate=True)
    a.output.write_bytes(cleaned)
