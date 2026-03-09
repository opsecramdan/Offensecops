"""
Report Generator — PDF pentest report dari scan engine findings
Uses ReportLab Platypus for professional layout
"""
import io
import logging
from datetime import datetime
from typing import List, Optional, Dict

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas

logger = logging.getLogger(__name__)

C_BG       = colors.HexColor('#0a0e1a')
C_ACCENT   = colors.HexColor('#6366f1')
C_TEXT     = colors.HexColor('#e2e8f0')
C_MUTED    = colors.HexColor('#64748b')
C_CRITICAL = colors.HexColor('#ef4444')
C_HIGH     = colors.HexColor('#f97316')
C_MEDIUM   = colors.HexColor('#eab308')
C_LOW      = colors.HexColor('#22c55e')
C_INFO     = colors.HexColor('#3b82f6')
C_WHITE    = colors.white
C_BORDER   = colors.HexColor('#1e293b')

SEV_COLORS = {'critical': C_CRITICAL, 'high': C_HIGH,
               'medium': C_MEDIUM, 'low': C_LOW, 'info': C_INFO}

OWASP_NAMES = {
    'A01:2021': 'Broken Access Control',
    'A02:2021': 'Cryptographic Failures',
    'A03:2021': 'Injection',
    'A04:2021': 'Insecure Design',
    'A05:2021': 'Security Misconfiguration',
    'A06:2021': 'Vulnerable & Outdated Components',
    'A07:2021': 'Identification & Authentication Failures',
    'A08:2021': 'Software & Data Integrity Failures',
    'A09:2021': 'Security Logging & Monitoring Failures',
    'A10:2021': 'Server-Side Request Forgery (SSRF)',
}

MODULE_DESC = {
    'port_scan': 'Port Scan — Nmap service version detection across TCP ports.',
    'web_scan': 'Web Scan — Nuclei template-based vulnerability scanning (CVE, misconfiguration).',
    'ssl_tls': 'SSL/TLS — Protocol version, cipher suite, and certificate validity.',
    'headers': 'Security Headers — HTTP response header analysis (HSTS, CSP, X-Frame-Options).',
    'subdomain': 'Subdomain Recon — Passive enumeration via certificate transparency and DNS.',
    'dns': 'DNS Check — SPF, DMARC, DNSSEC, and DNS record misconfiguration.',
    'cve_match': 'CVE Match — Service-to-CVE correlation via NIST NVD database.',
}


class ReportCanvas(canvas.Canvas):
    def __init__(self, *args, company_name="OffenSecOps", **kwargs):
        super().__init__(*args, **kwargs)
        self.company_name = company_name
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_page(self, page_count):
        w, h = A4
        self.setFillColor(C_BG)
        self.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
        self.setFillColor(C_ACCENT)
        self.rect(0, h - 14*mm, 2*mm, 14*mm, fill=1, stroke=0)
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(C_WHITE)
        self.drawString(8*mm, h - 9*mm, self.company_name.upper())
        self.setFont('Helvetica', 7)
        self.setFillColor(colors.HexColor('#94a3b8'))
        self.drawRightString(w - 8*mm, h - 9*mm, 'CONFIDENTIAL')
        self.setFillColor(C_BG)
        self.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        self.setFillColor(C_ACCENT)
        self.rect(0, 0, 2*mm, 10*mm, fill=1, stroke=0)
        self.setFont('Helvetica', 7)
        self.setFillColor(colors.HexColor('#94a3b8'))
        self.drawString(8*mm, 3.5*mm,
                        f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}')
        self.drawRightString(w - 8*mm, 3.5*mm,
                             f'Page {self._pageNumber} of {page_count}')
        self.setStrokeColor(C_ACCENT)
        self.setLineWidth(0.3)
        self.line(0, h - 14*mm, w, h - 14*mm)
        self.line(0, 10*mm, w, 10*mm)


def make_styles():
    return {
        'cover_title': ParagraphStyle('cover_title', fontSize=32,
            fontName='Helvetica-Bold', textColor=C_WHITE, leading=38),
        'cover_sub': ParagraphStyle('cover_sub', fontSize=14,
            fontName='Helvetica', textColor=colors.HexColor('#94a3b8'), leading=18),
        'cover_meta': ParagraphStyle('cover_meta', fontSize=10,
            fontName='Helvetica', textColor=C_MUTED, leading=14),
        'h1': ParagraphStyle('h1', fontSize=18, fontName='Helvetica-Bold',
            textColor=C_ACCENT, leading=22, spaceBefore=16, spaceAfter=8),
        'h3': ParagraphStyle('h3', fontSize=11, fontName='Helvetica-Bold',
            textColor=colors.HexColor('#94a3b8'), leading=14, spaceBefore=8, spaceAfter=4),
        'body': ParagraphStyle('body', fontSize=9, fontName='Helvetica',
            textColor=colors.HexColor('#cbd5e1'), leading=14,
            alignment=TA_JUSTIFY, spaceAfter=6),
        'label': ParagraphStyle('label', fontSize=8, fontName='Helvetica-Bold',
            textColor=C_MUTED, leading=10, spaceAfter=2),
        'toc': ParagraphStyle('toc', fontSize=10, fontName='Helvetica',
            textColor=colors.HexColor('#cbd5e1'), leading=16, spaceAfter=2),
    }


def hr():
    return HRFlowable(width='100%', thickness=0.5,
                      color=C_BORDER, spaceAfter=8, spaceBefore=4)


def stat_box(label, value, color=None):
    c = color or C_ACCENT
    data = [
        [Paragraph(f'<font size="20"><b>{value}</b></font>',
                   ParagraphStyle('', fontSize=20, fontName='Helvetica-Bold',
                                  textColor=c, leading=24, alignment=TA_CENTER))],
        [Paragraph(label, ParagraphStyle('', fontSize=7, fontName='Helvetica',
                                          textColor=C_MUTED, leading=10,
                                          alignment=TA_CENTER))],
    ]
    t = Table(data, colWidths=[35*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#111827')),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
    ]))
    return t


def build_cover(story, meta, styles):
    story.append(Spacer(1, 28*mm))
    story.append(Paragraph(
        '<font color="#6366f1">&#9632;</font>  ' + meta.get("company", "OffenSecOps"),
        ParagraphStyle('', fontSize=11, fontName='Helvetica-Bold',
                       textColor=C_ACCENT, leading=14)
    ))
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph('Penetration Test', styles['cover_sub']))
    story.append(Paragraph('Security Report', styles['cover_title']))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f'Target: <b>{meta.get("target", "N/A")}</b>',
                            styles['cover_sub']))
    story.append(Spacer(1, 20*mm))
    sep = Table([['']], colWidths=[120*mm])
    sep.setStyle(TableStyle([
        ('LINEBELOW', (0,0), (-1,-1), 2, C_ACCENT),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(sep)
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        f'Report Date: {datetime.now().strftime("%B %d, %Y")}', styles['cover_meta']))
    story.append(Paragraph('Classification: CONFIDENTIAL', styles['cover_meta']))
    story.append(Paragraph(
        f'Prepared by: {meta.get("author", "Red Team")}', styles['cover_meta']))
    rs = meta.get('risk_score')
    if rs is not None:
        story.append(Spacer(1, 16*mm))
        rc = (C_CRITICAL if rs >= 70 else C_HIGH if rs >= 40
              else C_MEDIUM if rs >= 20 else C_LOW)
        story.append(Paragraph(
            f'Overall Risk Score: <font color="#{rc.hexval()[1:]}"><b>{rs}/100</b></font>',
            ParagraphStyle('', fontSize=14, fontName='Helvetica-Bold',
                           textColor=C_WHITE, leading=18)
        ))
    story.append(PageBreak())


def build_toc(story, sections, styles):
    story.append(Paragraph('Table of Contents', styles['h1']))
    story.append(hr())
    for num, title in sections:
        story.append(Paragraph(f'{num}.  {title}', styles['toc']))
    story.append(PageBreak())


def build_executive_summary(story, summary, targets, styles):
    story.append(Paragraph('1. Executive Summary', styles['h1']))
    story.append(hr())
    story.append(Paragraph(
        'This report presents findings from a security assessment using automated '
        'vulnerability scanning, service enumeration, SSL/TLS analysis, DNS '
        'misconfiguration checks, and web application security testing.',
        styles['body']))
    story.append(Spacer(1, 6*mm))

    crit = summary.get('critical', 0)
    high = summary.get('high', 0)
    med  = summary.get('medium', 0)
    low  = summary.get('low', 0)
    total = summary.get('total', 0)
    rs   = summary.get('risk_score', 0)

    st = Table([[
        stat_box('Total', str(total), C_ACCENT),
        stat_box('Critical', str(crit), C_CRITICAL),
        stat_box('High', str(high), C_HIGH),
        stat_box('Medium', str(med), C_MEDIUM),
        stat_box('Low', str(low), C_LOW),
        stat_box('Risk Score', f'{rs}/100',
                 C_CRITICAL if rs >= 70 else C_HIGH if rs >= 40 else C_LOW),
    ]], colWidths=[35*mm]*6)
    st.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),
                             ('LEFTPADDING',(0,0),(-1,-1),3),
                             ('RIGHTPADDING',(0,0),(-1,-1),3)]))
    story.append(st)
    story.append(Spacer(1, 8*mm))

    if total > 0:
        bar_items = [(s, summary.get(s,0), SEV_COLORS[s])
                     for s in ['critical','high','medium','low']
                     if summary.get(s,0) > 0]
        if bar_items:
            bar_w = 160*mm
            widths = [b[1]/total * bar_w for b in bar_items]
            row = [[Paragraph('', ParagraphStyle(''))] * len(bar_items)]
            t = Table(row, colWidths=widths, rowHeights=[7*mm])
            cmds = [('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0),
                    ('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0)]
            for i, (_,_,c) in enumerate(bar_items):
                cmds.append(('BACKGROUND',(i,0),(i,0),c))
            t.setStyle(TableStyle(cmds))
            story.append(t)
            legend_row = [[Paragraph(
                f'<font color="#{c.hexval()[1:]}">&#9632;</font> {s}: {n}',
                ParagraphStyle('', fontSize=8, fontName='Helvetica',
                               textColor=C_TEXT, leading=12)
            ) for s,n,c in bar_items]]
            lt = Table(legend_row, colWidths=[40*mm]*len(bar_items))
            lt.setStyle(TableStyle([('TOPPADDING',(0,0),(-1,-1),4),
                                    ('LEFTPADDING',(0,0),(-1,-1),0)]))
            story.append(lt)
        story.append(Spacer(1, 6*mm))

    if targets:
        story.append(Paragraph('Assessed Targets', styles['h3']))
        tgt_data = [['Target', 'IP Address', 'Group', 'Status']]
        for t in targets[:20]:
            tgt_data.append([t.get('value',''), t.get('ip_address','N/A'),
                              t.get('group','N/A'), t.get('status','active')])
        tbl = Table(tgt_data, colWidths=[60*mm, 40*mm, 35*mm, 25*mm])
        tbl.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0), C_ACCENT),
            ('TEXTCOLOR',(0,0),(-1,0), C_WHITE),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('FONTNAME',(0,1),(-1,-1),'Helvetica'),
            ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),
             [colors.HexColor('#111827'), colors.HexColor('#0f172a')]),
            ('GRID',(0,0),(-1,-1),0.3, C_BORDER),
            ('TOPPADDING',(0,0),(-1,-1),5),
            ('BOTTOMPADDING',(0,0),(-1,-1),5),
            ('LEFTPADDING',(0,0),(-1,-1),6),
        ]))
        story.append(tbl)
    story.append(PageBreak())


def build_owasp_section(story, findings, styles):
    story.append(Paragraph('2. OWASP Top 10 Coverage', styles['h1']))
    story.append(hr())
    story.append(Paragraph(
        'Findings mapped to OWASP Top 10 (2021) categories.', styles['body']))
    story.append(Spacer(1, 6*mm))

    owasp_counts: Dict[str,int] = {}
    owasp_sevs: Dict[str,list] = {}
    for f in findings:
        cat = f.get('owasp_category','')
        if cat:
            owasp_counts[cat] = owasp_counts.get(cat,0) + 1
            owasp_sevs.setdefault(cat,[]).append(f.get('severity','info'))

    data = [['Category','Name','Findings','Worst Sev','Status']]
    sev_ord = ['critical','high','medium','low','info']
    for cat in sorted(OWASP_NAMES):
        count = owasp_counts.get(cat,0)
        sevs  = owasp_sevs.get(cat,[])
        worst = next((s for s in sev_ord if s in sevs),'info')
        sc = SEV_COLORS.get(worst, C_INFO) if count else C_MUTED
        status = 'AFFECTED' if count else 'PASS'
        data.append([
            Paragraph(f'<b>{cat}</b>',
                      ParagraphStyle('', fontSize=8, fontName='Helvetica-Bold',
                                     textColor=C_ACCENT if count else C_MUTED)),
            Paragraph(OWASP_NAMES[cat],
                      ParagraphStyle('', fontSize=8, fontName='Helvetica',
                                     textColor=C_TEXT if count else C_MUTED)),
            Paragraph(str(count) if count else '-',
                      ParagraphStyle('', fontSize=8, fontName='Helvetica-Bold',
                                     textColor=sc, alignment=TA_CENTER)),
            Paragraph(worst.upper() if count else '-',
                      ParagraphStyle('', fontSize=8, fontName='Helvetica-Bold',
                                     textColor=sc)),
            Paragraph(f'<b>{status}</b>',
                      ParagraphStyle('', fontSize=8, fontName='Helvetica-Bold',
                                     textColor=C_CRITICAL if count else C_LOW)),
        ])

    tbl = Table(data, colWidths=[28*mm,65*mm,22*mm,30*mm,20*mm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), C_ACCENT),
        ('TEXTCOLOR',(0,0),(-1,0), C_WHITE),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),8),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),
         [colors.HexColor('#111827'), colors.HexColor('#0f172a')]),
        ('GRID',(0,0),(-1,-1),0.3, C_BORDER),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('TOPPADDING',(0,0),(-1,-1),5),
        ('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),6),
        ('ALIGN',(2,1),(2,-1),'CENTER'),
    ]))
    story.append(tbl)
    story.append(PageBreak())


def build_findings_section(story, findings, styles, section_num=3):
    story.append(Paragraph(f'{section_num}. Technical Findings', styles['h1']))
    story.append(hr())
    if not findings:
        story.append(Paragraph('No findings recorded.', styles['body']))
        story.append(PageBreak())
        return

    sev_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
    sorted_f = sorted(findings,
                      key=lambda f: sev_order.get(f.get('severity','info'),4))

    for i, f in enumerate(sorted_f, 1):
        sev = f.get('severity','info')
        sc  = SEV_COLORS.get(sev, C_INFO)
        title = f.get('title','Untitled')

        meta_parts = []
        if f.get('module'):
            meta_parts.append(f'Module: {f["module"].replace("_"," ").title()}')
        if f.get('host'):
            p = f':{ f["port"]}' if f.get('port') else ''
            meta_parts.append(f'Host: {f["host"]}{p}')
        if f.get('cvss_score'):
            meta_parts.append(f'CVSS: {f["cvss_score"]:.1f}')
        if f.get('cve_ids'):
            meta_parts.append(f'CVE: {", ".join(f["cve_ids"][:2])}')
        if f.get('owasp_category'):
            meta_parts.append(f'OWASP: {f["owasp_category"]}')

        ht = Table([[
            Paragraph(f'<font color="#{sc.hexval()[1:]}"><b>#{i:02d} — {title}</b></font>',
                      ParagraphStyle('', fontSize=10, fontName='Helvetica-Bold',
                                     textColor=sc, leading=14)),
            Paragraph(f'<b>{sev.upper()}</b>',
                      ParagraphStyle('', fontSize=9, fontName='Helvetica-Bold',
                                     textColor=sc, alignment=TA_RIGHT)),
        ]], colWidths=[135*mm, 25*mm])
        ht.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#0f172a')),
            ('LINEBELOW',(0,0),(-1,-1),1.5, sc),
            ('TOPPADDING',(0,0),(-1,-1),6),
            ('BOTTOMPADDING',(0,0),(-1,-1),6),
            ('LEFTPADDING',(0,0),(-1,-1),8),
            ('RIGHTPADDING',(0,0),(-1,-1),8),
            ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ]))

        mt = Table([[Paragraph(
            '   |   '.join(meta_parts),
            ParagraphStyle('', fontSize=7, fontName='Helvetica',
                           textColor=C_MUTED, leading=10)
        )]], colWidths=[160*mm])
        mt.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#0f172a')),
            ('TOPPADDING',(0,0),(-1,-1),3),
            ('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('LEFTPADDING',(0,0),(-1,-1),8),
        ]))

        content_rows = []
        if f.get('description'):
            content_rows.append([
                Paragraph('Description', styles['label']),
                Paragraph(f['description'][:600],
                          ParagraphStyle('', fontSize=9, fontName='Helvetica',
                                         textColor=colors.HexColor('#cbd5e1'),
                                         leading=14, alignment=TA_JUSTIFY)),
            ])
        if f.get('evidence'):
            content_rows.append([
                Paragraph('Evidence', styles['label']),
                Paragraph(
                    f'<font face="Courier" size="8">{f["evidence"][:400]}</font>',
                    ParagraphStyle('', fontSize=8, fontName='Courier',
                                   textColor=colors.HexColor('#86efac'),
                                   backColor=colors.HexColor('#0f172a'),
                                   leading=12, leftIndent=4)),
            ])
        if f.get('remediation'):
            content_rows.append([
                Paragraph('Remediation', styles['label']),
                Paragraph(f['remediation'][:400],
                          ParagraphStyle('', fontSize=9, fontName='Helvetica',
                                         textColor=colors.HexColor('#86efac'),
                                         leading=13)),
            ])

        story.append(KeepTogether([ht, mt]))
        if content_rows:
            ct = Table(content_rows, colWidths=[25*mm, 135*mm])
            ct.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#111827')),
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('TOPPADDING',(0,0),(-1,-1),5),
                ('BOTTOMPADDING',(0,0),(-1,-1),5),
                ('LEFTPADDING',(0,0),(-1,-1),8),
                ('RIGHTPADDING',(0,0),(-1,-1),8),
                ('LINEBELOW',(0,-1),(-1,-1),0.3, C_BORDER),
            ]))
            story.append(ct)
        story.append(Spacer(1, 5*mm))

    story.append(PageBreak())


def generate_pentest_report(
    findings: List[dict],
    targets: List[dict],
    scan_jobs: List[dict],
    meta: Optional[dict] = None,
) -> bytes:
    if meta is None:
        meta = {}
    buf = io.BytesIO()
    styles = make_styles()

    sev_counts = {s:0 for s in ['critical','high','medium','low','info']}
    for f in findings:
        sev_counts[f.get('severity','info')] = \
            sev_counts.get(f.get('severity','info'),0) + 1

    total = len(findings)
    rs = min(100, int(
        sev_counts['critical']*10 + sev_counts['high']*5 +
        sev_counts['medium']*2  + sev_counts['low']*0.5
    ))
    summary = {**sev_counts, 'total': total, 'risk_score': rs}
    meta['risk_score'] = rs

    sections = [('1','Executive Summary'),('2','OWASP Top 10 Coverage'),
                ('3','Technical Findings'),('4','Methodology'),('5','Disclaimer')]

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=20*mm, bottomMargin=16*mm)
    story = []
    build_cover(story, meta, styles)
    build_toc(story, sections, styles)
    build_executive_summary(story, summary, targets, styles)
    build_owasp_section(story, findings, styles)
    build_findings_section(story, findings, styles, section_num=3)

    # Methodology
    story.append(Paragraph('4. Methodology', styles['h1']))
    story.append(hr())
    story.append(Paragraph(
        'Security assessment conducted using the following modules:', styles['body']))
    story.append(Spacer(1, 4*mm))
    for mod in set(f.get('module','') for f in findings if f.get('module')):
        if mod in MODULE_DESC:
            story.append(Paragraph(f'<b>&#8226;  {MODULE_DESC[mod]}</b>',
                ParagraphStyle('', fontSize=9, fontName='Helvetica',
                               textColor=C_TEXT, leading=14, leftIndent=8)))
    story.append(PageBreak())

    # Disclaimer
    story.append(Paragraph('5. Disclaimer', styles['h1']))
    story.append(hr())
    story.append(Paragraph(
        'This report is intended solely for the organization that commissioned this '
        'assessment. Findings are based on information available at assessment time. '
        'Security vulnerabilities change over time. Unauthorized disclosure is prohibited.',
        styles['body']))

    company = meta.get('company', 'OffenSecOps')
    doc.build(story,
              canvasmaker=lambda *a, **kw: ReportCanvas(*a, company_name=company, **kw))
    return buf.getvalue()
