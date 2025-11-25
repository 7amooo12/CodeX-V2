"""
PDF Report Generator for Security Analyzer
Creates professional, visual reports with charts and graphs
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from io import BytesIO
import os

# Import shared vulnerability section generator for consistency
from reports.vulnerability_section_generator import generate_vulnerability_section

class SecurityReportPDF:
    def __init__(self, filename="security_report.pdf"):
        # Ensure output directory exists
        output_dir = "D:\\project\\output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Update filename to include output directory
        if not os.path.isabs(filename):
            filename = os.path.join(output_dir, filename)
        
        self.filename = filename
        self.doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        self.styles = getSampleStyleSheet()
        self.story = []
        self.width, self.height = letter
        
        # Custom styles
        self.create_custom_styles()
    
    def create_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5,
            backColor=colors.HexColor('#ecf0f1')
        ))
        
        # Risk label styles
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            backColor=colors.HexColor('#c0392b'),
            borderPadding=3
        ))
        
        self.styles.add(ParagraphStyle(
            name='High',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            backColor=colors.HexColor('#e67e22'),
            borderPadding=3
        ))
        
        self.styles.add(ParagraphStyle(
            name='Medium',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            backColor=colors.HexColor('#f39c12'),
            borderPadding=3
        ))
        
        self.styles.add(ParagraphStyle(
            name='Low',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            backColor=colors.HexColor('#27ae60'),
            borderPadding=3
        ))
    
    def create_risk_pie_chart(self, risk_data):
        """Create a pie chart for risk distribution"""
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 150
        pie.height = 150
        
        # Data
        labels = []
        values = []
        colors_list = []
        
        if risk_data.get('critical', 0) > 0:
            labels.append('Critical')
            values.append(risk_data['critical'])
            colors_list.append(colors.HexColor('#c0392b'))
        
        if risk_data.get('high', 0) > 0:
            labels.append('High')
            values.append(risk_data['high'])
            colors_list.append(colors.HexColor('#e67e22'))
        
        if risk_data.get('medium', 0) > 0:
            labels.append('Medium')
            values.append(risk_data['medium'])
            colors_list.append(colors.HexColor('#f39c12'))
        
        if risk_data.get('low', 0) > 0:
            labels.append('Low')
            values.append(risk_data['low'])
            colors_list.append(colors.HexColor('#27ae60'))
        
        if not values:
            labels = ['No Findings']
            values = [1]
            colors_list = [colors.HexColor('#95a5a6')]
        
        pie.data = values
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(colors_list):
            pie.slices[i].fillColor = color
        
        # Legend
        legend = Legend()
        legend.x = 0
        legend.y = 100
        legend.dx = 8
        legend.dy = 8
        legend.fontName = 'Helvetica'
        legend.fontSize = 10
        legend.columnMaximum = 4
        legend.alignment = 'right'
        legend.colorNamePairs = [(colors_list[i], labels[i]) for i in range(len(labels))]
        
        drawing.add(pie)
        drawing.add(legend)
        
        return drawing
    
    def create_bar_chart(self, data_dict, title=""):
        """Create a bar chart using matplotlib"""
        fig, ax = plt.subplots(figsize=(8, 4))
        
        categories = list(data_dict.keys())
        values = list(data_dict.values())
        
        colors_map = {
            'Critical': '#c0392b',
            'High': '#e67e22',
            'Medium': '#f39c12',
            'Low': '#27ae60'
        }
        
        bar_colors = [colors_map.get(cat, '#3498db') for cat in categories]
        
        bars = ax.bar(categories, values, color=bar_colors, edgecolor='black', linewidth=1.2)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontweight='bold')
        
        ax.set_ylabel('Number of Findings', fontweight='bold')
        ax.set_title(title, fontweight='bold', fontsize=14)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='y', alpha=0.3, linestyle='--')
        
        plt.tight_layout()
        
        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return Image(img_buffer, width=6*inch, height=3*inch)
    
    def create_horizontal_bar(self, languages_data):
        """Create horizontal bar chart for languages"""
        if not languages_data:
            return None
        
        fig, ax = plt.subplots(figsize=(8, max(4, len(languages_data) * 0.5)))
        
        languages = list(languages_data.keys())
        counts = list(languages_data.values())
        
        bars = ax.barh(languages, counts, color='#3498db', edgecolor='black', linewidth=1)
        
        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            if width > 0:
                ax.text(width, bar.get_y() + bar.get_height()/2.,
                       f' {int(width)}',
                       ha='left', va='center', fontweight='bold')
        
        ax.set_xlabel('Number of Findings', fontweight='bold')
        ax.set_title('Security Findings by Language', fontweight='bold', fontsize=14)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        
        plt.tight_layout()
        
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return Image(img_buffer, width=6*inch, height=max(3*inch, len(languages_data) * 0.4 * inch))
    
    def add_title_page(self, project_name=""):
        """Add a professional title page"""
        self.story.append(Spacer(1, 2*inch))
        
        title = Paragraph(
            "🛡️ SECURITY ANALYSIS REPORT",
            self.styles['CustomTitle']
        )
        self.story.append(title)
        self.story.append(Spacer(1, 0.3*inch))
        
        subtitle = Paragraph(
            "Comprehensive Code Security Assessment",
            self.styles['Heading2']
        )
        subtitle.alignment = TA_CENTER
        self.story.append(subtitle)
        self.story.append(Spacer(1, 0.5*inch))
        
        if project_name:
            project = Paragraph(
                f"<b>Project:</b> {project_name}",
                self.styles['Normal']
            )
            project.alignment = TA_CENTER
            self.story.append(project)
            self.story.append(Spacer(1, 0.2*inch))
        
        date_text = Paragraph(
            f"<b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
            self.styles['Normal']
        )
        date_text.alignment = TA_CENTER
        self.story.append(date_text)
        
        self.story.append(Spacer(1, 1*inch))
        
        # Add disclaimer
        disclaimer = Paragraph(
            "<i>This report contains sensitive security information. "
            "Handle with care and distribute only to authorized personnel.</i>",
            self.styles['Normal']
        )
        disclaimer.alignment = TA_CENTER
        self.story.append(disclaimer)
        
        self.story.append(PageBreak())
    
    def add_executive_summary(self, risk_assessment, languages):
        """Add executive summary with charts"""
        self.story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Risk level with color
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        risk_colors = {
            'CRITICAL': colors.HexColor('#c0392b'),
            'HIGH': colors.HexColor('#e67e22'),
            'MEDIUM': colors.HexColor('#f39c12'),
            'LOW': colors.HexColor('#27ae60')
        }
        
        risk_color = risk_colors.get(risk_level, colors.grey)
        
        summary_data = [
            ['Overall Risk Level', Paragraph(f"<font color='white'><b>{risk_level}</b></font>", self.styles['Normal'])],
            ['Total Findings', str(risk_assessment.get('total_findings', 0))],
            ['Critical Issues', str(risk_assessment.get('critical', 0))],
            ['High Issues', str(risk_assessment.get('high', 0))],
            ['Medium Issues', str(risk_assessment.get('medium', 0))],
            ['Low Issues', str(risk_assessment.get('low', 0))],
            ['Languages Analyzed', ', '.join(languages) if languages else 'None']
        ]
        
        table = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
        ]))
        
        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Add pie chart
        if risk_assessment.get('total_findings', 0) > 0:
            self.story.append(Paragraph("Risk Distribution", self.styles['Heading3']))
            pie_chart = self.create_risk_pie_chart(risk_assessment)
            self.story.append(pie_chart)
            
            # Add bar chart
            self.story.append(Spacer(1, 0.2*inch))
            chart_data = {
                'Critical': risk_assessment.get('critical', 0),
                'High': risk_assessment.get('high', 0),
                'Medium': risk_assessment.get('medium', 0),
                'Low': risk_assessment.get('low', 0)
            }
            bar_chart = self.create_bar_chart(chart_data, "Findings by Severity")
            self.story.append(bar_chart)
        
        self.story.append(PageBreak())
    
    def add_dangerous_functions_section(self, security_analysis):
        """Add dangerous functions section with tables"""
        self.story.append(Paragraph("DANGEROUS FUNCTIONS DETECTED", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        from collections import defaultdict
        dangerous_by_lang = defaultdict(list)
        
        for file_path, data in security_analysis.items():
            for func in data.get("dangerous_functions", []):
                dangerous_by_lang[func.get("language", "unknown")].append(func)
        
        if not dangerous_by_lang:
            self.story.append(Paragraph("✓ No dangerous functions detected.", self.styles['Normal']))
            self.story.append(PageBreak())
            return
        
        # Create language chart
        lang_counts = {lang: len(funcs) for lang, funcs in dangerous_by_lang.items()}
        lang_chart = self.create_horizontal_bar(lang_counts)
        if lang_chart:
            self.story.append(lang_chart)
            self.story.append(Spacer(1, 0.3*inch))
        
        # Add findings by language
        for lang, funcs in list(dangerous_by_lang.items())[:5]:  # Limit to 5 languages
            self.story.append(Paragraph(f"{lang.upper()} - {len(funcs)} findings", self.styles['Heading3']))
            
            table_data = [['Function', 'Category', 'File', 'Line']]
            
            for func in funcs[:15]:  # Limit to 15 per language
                file_name = os.path.basename(func.get('file', 'unknown'))
                table_data.append([
                    func.get('function', 'unknown')[:30],
                    func.get('category', 'unknown')[:20],
                    file_name[:30],
                    str(func.get('line', '?'))
                ])
            
            table = Table(table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch, 0.8*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            
            self.story.append(table)
            self.story.append(Spacer(1, 0.2*inch))
        
        self.story.append(PageBreak())
    
    def add_taint_flows_section(self, taint_flows):
        """Add taint flow analysis section"""
        self.story.append(Paragraph("TAINT FLOW ANALYSIS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        if not taint_flows:
            self.story.append(Paragraph("✓ No direct taint flows detected.", self.styles['Normal']))
            self.story.append(PageBreak())
            return
        
        self.story.append(Paragraph(f"Found {len(taint_flows)} potential taint flows", self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        for i, flow in enumerate(taint_flows[:20], 1):  # Limit to 20
            flow_data = [
                ['Flow #', str(i)],
                ['Risk Level', flow.get('risk', flow.get('category', 'HIGH'))],
                ['File', os.path.basename(flow.get('file', 'unknown'))],
                ['Source', f"{flow.get('source', 'unknown')} (line {flow.get('source_line', flow.get('line', '?'))})"],
                ['Sink', f"{flow.get('sink', 'N/A')} (line {flow.get('sink_line', '?')})"],
                ['Description', str(flow.get('description', flow.get('context', 'No description')))[:100]]
            ]
            
            table = Table(flow_data, colWidths=[1.5*inch, 4.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgoldenrodyellow),
                ('FONTSIZE', (0, 0), (-1, -1), 9)
            ]))
            
            self.story.append(table)
            self.story.append(Spacer(1, 0.15*inch))
        
        self.story.append(PageBreak())
    
    def add_secrets_section(self, security_analysis):
        """Add hardcoded secrets section"""
        self.story.append(Paragraph("HARDCODED SECRETS & CREDENTIALS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        all_secrets = []
        for file_path, data in security_analysis.items():
            all_secrets.extend(data.get("secrets", []))
        
        if not all_secrets:
            self.story.append(Paragraph("✓ No hardcoded secrets detected.", self.styles['Normal']))
            self.story.append(PageBreak())
            return
        
        # Count by type
        secret_types = {}
        for secret in all_secrets:
            stype = secret.get('type', 'unknown')
            secret_types[stype] = secret_types.get(stype, 0) + 1
        
        # Chart
        if len(secret_types) > 1:
            chart = self.create_bar_chart(secret_types, "Secrets by Type")
            self.story.append(chart)
            self.story.append(Spacer(1, 0.3*inch))
        
        self.story.append(Paragraph(f"Total secrets found: {len(all_secrets)}", self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Table of secrets (first 20)
        table_data = [['Type', 'File', 'Line', 'Preview']]
        
        for secret in all_secrets[:20]:
            file_name = os.path.basename(secret.get('file', 'unknown'))
            value = secret.get('value', 'N/A')
            value_preview = value[:40] + "..." if len(value) > 40 else value
            
            table_data.append([
                secret.get('type', 'unknown')[:15],
                file_name[:25],
                str(secret.get('line', 'N/A')),
                value_preview
            ])
        
        table = Table(table_data, colWidths=[1.2*inch, 1.8*inch, 0.6*inch, 2.4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
        ]))
        
        self.story.append(table)
        self.story.append(PageBreak())
    
    def add_quality_findings_section(self, quality_results):
        """Add code quality and maintainability findings section"""
        self.story.append(Paragraph("CODE QUALITY & MAINTAINABILITY ANALYSIS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        if not quality_results or 'findings' not in quality_results:
            self.story.append(Paragraph(
                "✓ Quality analysis not performed or module not loaded.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        findings = quality_results['findings']
        summary = quality_results.get('summary', {})
        
        # Summary statistics with visual styling
        total_issues = summary.get('total_issues', 0)
        
        if total_issues == 0:
            self.story.append(Paragraph(
                "✓ No code quality issues detected! Your code follows best practices.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        summary_text = f"""
        <b>Total Quality Issues: {total_issues}</b><br/>
        <font color="#e67e22">● Empty Catch Blocks: {summary.get('total_empty_catch', 0)}</font><br/>
        <font color="#c0392b">● Infinite Loops: {summary.get('total_infinite_loops', 0)}</font><br/>
        <font color="#f39c12">● Dead/Unreachable Code: {summary.get('total_dead_code', 0)}</font><br/>
        <font color="#3498db">● Naming Inconsistencies: {summary.get('total_naming_issues', 0)}</font><br/>
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.3*inch))
        
        # 1. EMPTY CATCH BLOCKS
        if findings.get('empty_catch_blocks'):
            empty_catch = findings['empty_catch_blocks']
            self.story.append(Paragraph(
                f"<b><font color='#e67e22'>⚠️ EMPTY CATCH BLOCKS - {len(empty_catch)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>Empty catch blocks suppress errors without handling them, making debugging difficult.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Language', 'Code Snippet']]
            
            for i, finding in enumerate(empty_catch[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:20]
                line = str(finding.get('line', 'N/A'))
                language = finding.get('language', 'N/A')[:12]
                snippet = finding.get('code_snippet', '')[:40]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    language,
                    snippet
                ])
            
            catch_table = Table(table_data, colWidths=[0.3*inch, 1.6*inch, 0.5*inch, 0.8*inch, 2.8*inch])
            catch_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e67e22')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightyellow, colors.white])
            ]))
            
            self.story.append(catch_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Add proper error handling logic inside catch blocks<br/>"
                "• At minimum, log the error for debugging purposes<br/>"
                "• Consider rethrowing if you can't handle the error",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 2. INFINITE LOOPS
        if findings.get('infinite_loops'):
            infinite_loops = findings['infinite_loops']
            self.story.append(Paragraph(
                f"<b><font color='#c0392b'>🔥 INFINITE LOOPS - {len(infinite_loops)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>Infinite loops without break conditions can cause application hangs and resource exhaustion.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Language', 'Code Pattern']]
            
            for i, finding in enumerate(infinite_loops[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:20]
                line = str(finding.get('line', 'N/A'))
                language = finding.get('language', 'N/A')[:12]
                snippet = finding.get('code_snippet', '')[:40]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    language,
                    snippet
                ])
            
            loop_table = Table(table_data, colWidths=[0.3*inch, 1.6*inch, 0.5*inch, 0.8*inch, 2.8*inch])
            loop_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
            ]))
            
            self.story.append(loop_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Add explicit break conditions to infinite loops<br/>"
                "• Use event-driven patterns instead of polling loops<br/>"
                "• Add timeout mechanisms for safety",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 3. DEAD/UNREACHABLE CODE
        if findings.get('dead_code'):
            dead_code = findings['dead_code']
            self.story.append(Paragraph(
                f"<b><font color='#f39c12'>⚡ DEAD/UNREACHABLE CODE - {len(dead_code)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>Unreachable code clutters the codebase and can confuse developers.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Type', 'Code Preview']]
            
            for i, finding in enumerate(dead_code[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:20]
                line = str(finding.get('line', 'N/A'))
                dead_type = finding.get('type', 'N/A')[:20]
                snippet = finding.get('code_snippet', '')[:35]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    dead_type,
                    snippet
                ])
            
            dead_table = Table(table_data, colWidths=[0.3*inch, 1.5*inch, 0.5*inch, 1.6*inch, 2.1*inch])
            dead_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f39c12')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lemonchiffon, colors.white])
            ]))
            
            self.story.append(dead_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Remove all unreachable code after return statements<br/>"
                "• Clean up dead code paths to improve maintainability<br/>"
                "• Use static analysis tools to detect dead code regularly",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 4. NAMING INCONSISTENCIES
        if findings.get('inconsistent_naming'):
            naming_issues = findings['inconsistent_naming']
            self.story.append(Paragraph(
                f"<b><font color='#3498db'>📝 NAMING INCONSISTENCIES - {len(naming_issues)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>Inconsistent naming conventions reduce code readability and maintainability.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Identifier', 'Actual', 'Expected']]
            
            for i, finding in enumerate(naming_issues[:25], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:18]
                line = str(finding.get('line', 'N/A'))
                identifier = finding.get('identifier', 'N/A')[:20]
                actual = finding.get('actual_convention', 'N/A')[:15]
                expected = finding.get('expected_convention', 'N/A')[:15]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    identifier,
                    actual,
                    expected
                ])
            
            naming_table = Table(table_data, colWidths=[0.3*inch, 1.4*inch, 0.5*inch, 1.5*inch, 1.1*inch, 1.2*inch])
            naming_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightblue, colors.white])
            ]))
            
            self.story.append(naming_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Follow consistent naming conventions for your language<br/>"
                "• Python: snake_case for functions/variables, PascalCase for classes<br/>"
                "• JavaScript/Java: camelCase for functions/variables, PascalCase for classes<br/>"
                "• Use linters to enforce naming conventions automatically",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # Statistics breakdown
        if summary.get('issues_by_language'):
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph("<b>Issues by Language:</b>", self.styles['Heading3']))
            
            lang_data = [['Language', 'Issues', 'Percentage']]
            total = summary['total_issues']
            
            for lang, count in sorted(summary['issues_by_language'].items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = f"{(count/total*100):.1f}%"
                lang_data.append([lang.title(), str(count), percentage])
            
            lang_table = Table(lang_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            lang_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white])
            ]))
            
            self.story.append(lang_table)
        
        self.story.append(PageBreak())
    
    def add_antipattern_findings_section(self, antipattern_results):
        """Add anti-pattern and security issues findings section"""
        self.story.append(Paragraph("ANTI-PATTERN & SECURITY ISSUES DETECTION", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        if not antipattern_results or 'findings' not in antipattern_results:
            self.story.append(Paragraph(
                "✓ Anti-pattern analysis not performed or module not loaded.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        findings = antipattern_results['findings']
        summary = antipattern_results.get('summary', {})
        
        # Summary statistics
        total_issues = summary.get('total_issues', 0)
        
        if total_issues == 0:
            self.story.append(Paragraph(
                "✓ No anti-patterns or security issues detected! Your code follows best practices.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        summary_text = f"""
        <b>Total Anti-Pattern Issues: {total_issues}</b><br/>
        <font color="#c0392b">● Password Variables: {summary.get('total_password_vars', 0)}</font><br/>
        <font color="#c0392b">● SQL Concatenation: {summary.get('total_sql_concat', 0)}</font><br/>
        <font color="#e67e22">● API Without Timeout: {summary.get('total_api_timeout', 0)}</font><br/>
        <font color="#e67e22">● Unsafe File Paths: {summary.get('total_unsafe_paths', 0)}</font><br/>
        <font color="#f39c12">● Dead Code: {summary.get('total_dead_code', 0)}</font><br/>
        <font color="#c0392b">● .env Issues: {summary.get('total_env_issues', 0)}</font><br/>
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.3*inch))
        
        # 1. PASSWORD VARIABLES
        if findings.get('password_variables'):
            password_vars = findings['password_variables']
            self.story.append(Paragraph(
                f"<b><font color='#c0392b'>🔐 PASSWORD/SECRET VARIABLES - {len(password_vars)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>Hardcoded passwords and secrets pose critical security risks.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Variable', 'Language', 'Severity']]
            
            for i, finding in enumerate(password_vars[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:18]
                line = str(finding.get('line', 'N/A'))
                var_name = finding.get('variable_name', 'N/A')[:20]
                language = finding.get('language', 'N/A')[:10]
                severity = finding.get('severity', 'critical').upper()
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    var_name,
                    language,
                    severity
                ])
            
            pwd_table = Table(table_data, colWidths=[0.3*inch, 1.5*inch, 0.5*inch, 1.5*inch, 0.8*inch, 0.9*inch])
            pwd_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('ALIGN', (5, 0), (5, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
            ]))
            
            self.story.append(pwd_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Use environment variables instead of hardcoded secrets<br/>"
                "• Implement proper secret management (Vault, AWS Secrets Manager)<br/>"
                "• Never commit secrets to version control",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 2. SQL CONCATENATION
        if findings.get('sql_concatenation'):
            sql_issues = findings['sql_concatenation']
            self.story.append(Paragraph(
                f"<b><font color='#c0392b'>💉 SQL INJECTION RISKS - {len(sql_issues)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>SQL queries built with string concatenation are vulnerable to SQL injection attacks.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Pattern', 'Language']]
            
            for i, finding in enumerate(sql_issues[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:22]
                line = str(finding.get('line', 'N/A'))
                pattern = finding.get('pattern', 'N/A')[:25]
                language = finding.get('language', 'N/A')[:12]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    pattern,
                    language
                ])
            
            sql_table = Table(table_data, colWidths=[0.3*inch, 1.8*inch, 0.5*inch, 2.2*inch, 1.2*inch])
            sql_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
            ]))
            
            self.story.append(sql_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Use parameterized queries with placeholders (?, %s)<br/>"
                "• Implement ORM libraries (SQLAlchemy, Sequelize, Django ORM)<br/>"
                "• Never concatenate user input into SQL queries",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 3. API WITHOUT TIMEOUT
        if findings.get('api_without_timeout'):
            api_issues = findings['api_without_timeout']
            self.story.append(Paragraph(
                f"<b><font color='#e67e22'>⏱️ API CALLS WITHOUT TIMEOUT - {len(api_issues)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>API calls without timeout can cause application hangs and resource exhaustion.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Method', 'Language']]
            
            for i, finding in enumerate(api_issues[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:25]
                line = str(finding.get('line', 'N/A'))
                method = finding.get('method', 'N/A')[:20]
                language = finding.get('language', 'N/A')[:12]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    method,
                    language
                ])
            
            api_table = Table(table_data, colWidths=[0.3*inch, 2*inch, 0.5*inch, 1.7*inch, 1.5*inch])
            api_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e67e22')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightyellow, colors.white])
            ]))
            
            self.story.append(api_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Python: Add timeout parameter to requests.get/post()<br/>"
                "• JavaScript: Use AbortController for fetch() or timeout config for axios<br/>"
                "• Set reasonable timeout values (e.g., 30 seconds for normal API calls)",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 4. UNSAFE FILE PATHS
        if findings.get('unsafe_file_paths'):
            path_issues = findings['unsafe_file_paths']
            self.story.append(Paragraph(
                f"<b><font color='#e67e22'>📁 UNSAFE FILE PATH ACCESS - {len(path_issues)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>File operations with unsanitized user input can lead to path traversal attacks.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Operation', 'Language']]
            
            for i, finding in enumerate(path_issues[:20], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:22]
                line = str(finding.get('line', 'N/A'))
                operation = finding.get('operation', 'N/A')[:22]
                language = finding.get('language', 'N/A')[:12]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    operation,
                    language
                ])
            
            path_table = Table(table_data, colWidths=[0.3*inch, 1.8*inch, 0.5*inch, 2*inch, 1.4*inch])
            path_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e67e22')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightyellow, colors.white])
            ]))
            
            self.story.append(path_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Validate and sanitize all file paths from user input<br/>"
                "• Use os.path.join() or path.join() for safe path construction<br/>"
                "• Check paths against allowed directories (whitelist approach)<br/>"
                "• Reject paths containing '..' or absolute paths from users",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.2*inch))
        
        # 5. ENV FILE ISSUES
        if findings.get('env_issues'):
            env_issues = findings['env_issues']
            self.story.append(Paragraph(
                f"<b><font color='#c0392b'>⚙️ .ENV FILE SECURITY - {len(env_issues)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            self.story.append(Paragraph(
                "<i>.env files containing secrets must be properly secured.</i>",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'File', 'Line', 'Issue']]
            
            for i, finding in enumerate(env_issues[:15], 1):
                file_name = os.path.basename(finding.get('file', 'N/A'))[:30]
                line = str(finding.get('line', 'N/A'))
                issue = finding.get('type', 'N/A')[:30]
                
                table_data.append([
                    str(i),
                    file_name,
                    line,
                    issue
                ])
            
            env_table = Table(table_data, colWidths=[0.3*inch, 2.5*inch, 0.5*inch, 2.7*inch])
            env_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
            ]))
            
            self.story.append(env_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            self.story.append(Paragraph(
                "<b>Recommendations:</b><br/>"
                "• Ensure .env files are in .gitignore<br/>"
                "• Never commit .env files to version control<br/>"
                "• Provide .env.example with placeholder values<br/>"
                "• Use proper secret management in production",
                self.styles['Normal']
            ))
        
        self.story.append(PageBreak())
    
    def add_vulnerability_scan_section(self, vuln_scan_data):
        """
        Add comprehensive dependency vulnerability scan section with CVE mapping
        Uses shared vulnerability_section_generator for consistency across all PDFs
        """
        # Use the shared generator function - handles ALL vulnerability rendering
        generate_vulnerability_section(self.story, vuln_scan_data, self.styles)
    
    def add_recommendations_section(self):
        """Add security and quality recommendations"""
        self.story.append(Paragraph("SECURITY & QUALITY RECOMMENDATIONS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        recommendations = [
            ("🔴 CRITICAL", [
                "Remove all hardcoded secrets and passwords immediately",
                "Fix SQL injection vulnerabilities - use parameterized queries",
                "Fix code execution vulnerabilities (eval, exec)",
                "Address command injection flaws",
                "Remediate insecure deserialization",
                "Fix infinite loops that can cause system hangs",
                "Secure .env files and never commit them to version control"
            ]),
            ("🟠 HIGH", [
                "Implement input validation for all user inputs",
                "Use parameterized queries for ALL database operations",
                "Replace weak cryptographic algorithms",
                "Sanitize all file paths from user input",
                "Add proper error handling in empty catch blocks",
                "Add timeout to all API/HTTP requests",
                "Validate file paths against path traversal attacks"
            ]),
            ("🟡 MEDIUM", [
                "Implement logging and monitoring",
                "Set up automated security scanning",
                "Conduct regular security code reviews",
                "Use secret management tools (Vault, AWS Secrets Manager)",
                "Remove dead/unreachable code to improve maintainability",
                "Add timeout parameters to prevent resource exhaustion"
            ]),
            ("🟢 BEST PRACTICES", [
                "Implement defense-in-depth strategy",
                "Follow principle of least privilege",
                "Keep dependencies up to date",
                "Document security assumptions",
                "Enforce consistent naming conventions across the codebase",
                "Use linters and formatters for code quality",
                "Use environment variables for configuration",
                "Implement ORM libraries instead of raw SQL"
            ])
        ]
        
        for priority, items in recommendations:
            self.story.append(Paragraph(priority, self.styles['Heading3']))
            
            for item in items:
                bullet = Paragraph(f"• {item}", self.styles['Normal'])
                self.story.append(bullet)
                self.story.append(Spacer(1, 0.05*inch))
            
            self.story.append(Spacer(1, 0.15*inch))
        
        self.story.append(PageBreak())
    
    def add_footer(self, canvas, doc):
        """Add footer to each page"""
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.drawString(inch, 0.5 * inch, f"Page {doc.page}")
        canvas.drawRightString(
            self.width - inch,
            0.5 * inch,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        canvas.restoreState()
    
    def add_file_tree_section(self, file_tree_text, security_data):
        """Add beautifully formatted file tree hierarchy section with colors"""
        self.story.append(Paragraph("FILE TREE HIERARCHY WITH RISK INDICATORS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Add legend box with colors
        legend_data = [
            ['Risk Level', 'Indicator', 'Description'],
            ['CRITICAL', '●', 'Immediate attention required - Critical vulnerabilities'],
            ['HIGH', '●', 'Review and fix soon - High risk issues'],
            ['MEDIUM', '●', 'Security concern - Should be addressed'],
            ['LOW', '●', 'Minor issue - Low priority'],
            ['CLEAN', '●', 'No security issues detected']
        ]
        
        legend_table = Table(legend_data, colWidths=[1.5*inch, 0.7*inch, 3.8*inch])
        legend_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            
            # Color the indicators
            ('BACKGROUND', (1, 1), (1, 1), colors.HexColor('#c0392b')),  # Critical
            ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#c0392b')),
            ('BACKGROUND', (1, 2), (1, 2), colors.HexColor('#e67e22')),  # High
            ('TEXTCOLOR', (1, 2), (1, 2), colors.HexColor('#e67e22')),
            ('BACKGROUND', (1, 3), (1, 3), colors.HexColor('#f39c12')),  # Medium
            ('TEXTCOLOR', (1, 3), (1, 3), colors.HexColor('#f39c12')),
            ('BACKGROUND', (1, 4), (1, 4), colors.HexColor('#27ae60')),  # Low
            ('TEXTCOLOR', (1, 4), (1, 4), colors.HexColor('#27ae60')),
            ('BACKGROUND', (1, 5), (1, 5), colors.HexColor('#95a5a6')),  # Clean
            ('TEXTCOLOR', (1, 5), (1, 5), colors.HexColor('#95a5a6')),
            
            ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (1, 1), (1, -1), 16),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ('FONTSIZE', (0, 1), (-1, -1), 9)
        ]))
        
        self.story.append(legend_table)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Calculate file risks for coloring
        file_risks = {}
        if security_data:
            for file_path, data in security_data.items():
                risk_score = 0
                risk_score += len(data.get('dangerous_functions', [])) * 10
                risk_score += len([s for s in data.get('secrets', []) if s['type'] in ['aws_key', 'private_key', 'github_token']]) * 15
                risk_score += len(data.get('taint_sources', [])) * 5
                
                if risk_score >= 50:
                    file_risks[file_path] = 'critical'
                elif risk_score >= 20:
                    file_risks[file_path] = 'high'
                elif risk_score >= 5:
                    file_risks[file_path] = 'medium'
                elif risk_score > 0:
                    file_risks[file_path] = 'low'
        
        # Parse and format file tree with colors
        lines = file_tree_text.split('\n')
        
        # Create table data for structured tree view
        tree_items = []
        for line in lines[3:]:  # Skip header
            if not line.strip() or 'Legend:' in line or '=' in line:
                continue
            if len(tree_items) >= 50:  # Limit to 50 items
                break
                
            # Detect risk level and file info
            risk_color = colors.HexColor('#95a5a6')  # Default gray
            risk_text = ''
            
            if '🔥' in line or 'CRITICAL' in line:
                risk_color = colors.HexColor('#c0392b')
                risk_text = 'CRITICAL'
            elif '⚠️' in line or 'HIGH' in line:
                risk_color = colors.HexColor('#e67e22')
                risk_text = 'HIGH'
            elif '🟡' in line or 'MEDIUM' in line:
                risk_color = colors.HexColor('#f39c12')
                risk_text = 'MEDIUM'
            elif '🟢' in line or 'LOW' in line:
                risk_color = colors.HexColor('#27ae60')
                risk_text = 'LOW'
            elif '✓' in line:
                risk_text = 'CLEAN'
            
            # Clean the line
            clean_line = line.replace('📁', '').replace('📦', '').replace('🔥', '').replace('⚠️', '').replace('🟡', '').replace('🟢', '').replace('✓', '')
            clean_line = clean_line.replace('[CRITICAL]', '').replace('[HIGH]', '').replace('[MEDIUM]', '').replace('[LOW]', '').strip()
            
            if clean_line and len(clean_line) > 2:
                # Determine indent level
                indent = len(line) - len(line.lstrip())
                indent_text = '  ' * (indent // 2)
                
                # Check if directory
                is_dir = '/' in clean_line or 'DIR' in line.upper()
                icon = '📁' if is_dir else '📄'
                
                tree_items.append([
                    Paragraph(f"<font name='Courier' size='8'>{indent_text}{icon} {clean_line[:60]}</font>", self.styles['Normal']),
                    Paragraph(f"<font color='white'><b>{risk_text}</b></font>" if risk_text else '', self.styles['Normal'])
                ])
        
        if tree_items:
            # Create styled table
            tree_table = Table(tree_items, colWidths=[4.5*inch, 1.5*inch])
            
            # Build style with alternating row colors and risk-based backgrounds
            table_style = [
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 0), (0, -1), [colors.whitesmoke, colors.white]),
            ]
            
            # Color-code the risk column
            for i, item in enumerate(tree_items):
                if len(item) > 1:
                    risk_str = item[1].text if hasattr(item[1], 'text') else ''
                    if 'CRITICAL' in risk_str:
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#c0392b')))
                    elif 'HIGH' in risk_str:
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#e67e22')))
                    elif 'MEDIUM' in risk_str:
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#f39c12')))
                    elif 'LOW' in risk_str:
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#27ae60')))
            
            tree_table.setStyle(TableStyle(table_style))
            self.story.append(tree_table)
        
        self.story.append(PageBreak())
    
    def add_findings_table_section(self, deduplicated_data):
        """Add beautifully formatted intelligent findings table with colors"""
        self.story.append(Paragraph("INTELLIGENT FINDINGS TABLE (DEDUPLICATED)", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Add summary statistics box
        total_dangerous = len(deduplicated_data.get('dangerous_functions', {}))
        total_secrets = len(deduplicated_data.get('secrets', {}))
        total_taints = len(deduplicated_data.get('taint_sources', {}))
        total_fileops = len(deduplicated_data.get('file_network_ops', {}))
        
        summary_data = [
            ['Category', 'Unique Findings', 'Status'],
            ['Dangerous Functions', str(total_dangerous), '⚠️' if total_dangerous > 0 else '✓'],
            ['Hardcoded Secrets', str(total_secrets), '⚠️' if total_secrets > 0 else '✓'],
            ['Taint Sources', str(total_taints), '⚠️' if total_taints > 0 else '✓'],
            ['File/Network Ops', str(total_fileops), '⚠️' if total_fileops > 0 else '✓']
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lavender, colors.whitesmoke]),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10)
        ]))
        
        self.story.append(summary_table)
        self.story.append(Spacer(1, 0.3*inch))
        
        # 1. DANGEROUS FUNCTIONS TABLE
        if deduplicated_data.get('dangerous_functions'):
            self.story.append(Paragraph("🔴 DANGEROUS FUNCTIONS", self.styles['Heading3']))
            self.story.append(Spacer(1, 0.1*inch))
            
            func_data = [['File', 'Function', 'Category', 'Lines', 'Count', 'Risk']]
            
            for key, data in sorted(deduplicated_data['dangerous_functions'].items(), 
                                    key=lambda x: x[1]['count'], reverse=True)[:20]:
                file_short = os.path.basename(data['file'])[:25]
                func_short = data['function'][:18]
                category_short = data['category'][:16]
                
                from utils.enhanced_analysis import format_line_numbers
                line_str = format_line_numbers(data['lines'])[:12]
                count = data['count']
                
                # Determine risk
                if data['category'] in ['code_execution', 'command_injection', 'deserialization']:
                    risk = 'CRITICAL'
                elif data['category'] in ['sql_injection', 'buffer_overflow']:
                    risk = 'HIGH'
                else:
                    risk = 'MEDIUM'
                
                func_data.append([file_short, func_short, category_short, line_str, str(count), risk])
            
            func_table = Table(func_data, colWidths=[1.4*inch, 1.2*inch, 1.2*inch, 0.8*inch, 0.5*inch, 0.9*inch])
            
            # Build complex styling
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (4, 0), (4, -1), 'CENTER'),
                ('ALIGN', (5, 0), (5, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]
            
            # Color-code risk column
            for i in range(1, len(func_data)):
                risk_level = func_data[i][-1]
                if risk_level == 'CRITICAL':
                    table_style.append(('BACKGROUND', (5, i), (5, i), colors.HexColor('#c0392b')))
                    table_style.append(('TEXTCOLOR', (5, i), (5, i), colors.white))
                elif risk_level == 'HIGH':
                    table_style.append(('BACKGROUND', (5, i), (5, i), colors.HexColor('#e67e22')))
                    table_style.append(('TEXTCOLOR', (5, i), (5, i), colors.white))
                else:
                    table_style.append(('BACKGROUND', (5, i), (5, i), colors.HexColor('#f39c12')))
                    table_style.append(('TEXTCOLOR', (5, i), (5, i), colors.white))
                table_style.append(('FONTNAME', (5, i), (5, i), 'Helvetica-Bold'))
            
            func_table.setStyle(TableStyle(table_style))
            self.story.append(func_table)
            self.story.append(Spacer(1, 0.3*inch))
        
        # 2. SECRETS TABLE
        if deduplicated_data.get('secrets'):
            self.story.append(Paragraph("🔑 HARDCODED SECRETS", self.styles['Heading3']))
            self.story.append(Spacer(1, 0.1*inch))
            
            secret_data = [['File', 'Secret Type', 'Lines', 'Count', 'Severity']]
            
            for key, data in sorted(deduplicated_data['secrets'].items(), 
                                    key=lambda x: x[1]['count'], reverse=True)[:15]:
                file_short = os.path.basename(data['file'])[:28]
                type_short = data['type'].replace('_', ' ').title()[:25]
                
                from utils.enhanced_analysis import format_line_numbers
                line_str = format_line_numbers(data['lines'])[:12]
                count = data['count']
                
                # Determine severity
                if data['type'] in ['aws_key', 'private_key', 'github_token', 'stripe_key']:
                    severity = 'CRITICAL'
                else:
                    severity = 'HIGH'
                
                secret_data.append([file_short, type_short, line_str, str(count), severity])
            
            secret_table = Table(secret_data, colWidths=[1.8*inch, 2*inch, 0.8*inch, 0.6*inch, 0.8*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#8e44ad')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (3, 0), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.mistyrose, colors.white])
            ]
            
            # Color-code severity
            for i in range(1, len(secret_data)):
                severity = secret_data[i][-1]
                if severity == 'CRITICAL':
                    table_style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor('#c0392b')))
                    table_style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
                else:
                    table_style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor('#e67e22')))
                    table_style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
                table_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))
            
            secret_table.setStyle(TableStyle(table_style))
            self.story.append(secret_table)
            self.story.append(Spacer(1, 0.3*inch))
        
        # 3. TAINT SOURCES TABLE
        if deduplicated_data.get('taint_sources'):
            self.story.append(Paragraph("🚰 USER INPUT SOURCES (TAINT ORIGINS)", self.styles['Heading3']))
            self.story.append(Spacer(1, 0.1*inch))
            
            taint_data = [['File', 'Input Source', 'Language', 'Lines', 'Count']]
            
            for key, data in sorted(deduplicated_data['taint_sources'].items(), 
                                    key=lambda x: x[1]['count'], reverse=True)[:15]:
                file_short = os.path.basename(data['file'])[:28]
                source_short = data['source'][:30]
                lang = data['language'][:10]
                
                from utils.enhanced_analysis import format_line_numbers
                line_str = format_line_numbers(data['lines'])[:12]
                count = data['count']
                
                taint_data.append([file_short, source_short, lang, line_str, str(count)])
            
            taint_table = Table(taint_data, colWidths=[1.6*inch, 2*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            taint_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (4, 0), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightblue, colors.white])
            ]))
            
            self.story.append(taint_table)
            self.story.append(Spacer(1, 0.3*inch))
        
        # 4. FILE/NETWORK OPERATIONS TABLE
        if deduplicated_data.get('file_network_ops'):
            self.story.append(Paragraph("📂 FILE & NETWORK OPERATIONS", self.styles['Heading3']))
            self.story.append(Spacer(1, 0.1*inch))
            
            fileop_data = [['File', 'Operation Type', 'Lines', 'Count', 'Risk']]
            
            for key, data in sorted(deduplicated_data['file_network_ops'].items(), 
                                    key=lambda x: x[1]['count'], reverse=True)[:15]:
                file_short = os.path.basename(data['file'])[:28]
                op_short = data['operation'].replace('_', ' ').title()[:25]
                
                from utils.enhanced_analysis import format_line_numbers
                line_str = format_line_numbers(data['lines'])[:12]
                count = data['count']
                
                # Determine risk
                if data['operation'] in ['file_delete', 'download']:
                    risk = 'HIGH'
                else:
                    risk = 'MEDIUM'
                
                fileop_data.append([file_short, op_short, line_str, str(count), risk])
            
            fileop_table = Table(fileop_data, colWidths=[1.8*inch, 2*inch, 0.8*inch, 0.6*inch, 0.8*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16a085')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (3, 0), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightcyan, colors.white])
            ]
            
            # Color-code risk
            for i in range(1, len(fileop_data)):
                risk = fileop_data[i][-1]
                if risk == 'HIGH':
                    table_style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor('#e67e22')))
                    table_style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
                else:
                    table_style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor('#f39c12')))
                    table_style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
                table_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))
            
            fileop_table.setStyle(TableStyle(table_style))
            self.story.append(fileop_table)
        
        self.story.append(PageBreak())
    
    def add_framework_findings_section(self, framework_findings):
        """Add framework-specific security findings section"""
        self.story.append(Paragraph("FRAMEWORK-SPECIFIC SECURITY FINDINGS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        if not framework_findings or (len(framework_findings) == 1 and 'error' in framework_findings[0]):
            self.story.append(Paragraph(
                "✓ No framework-specific security issues detected or module not loaded.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        # Group findings by severity
        from collections import defaultdict
        findings_by_severity = defaultdict(list)
        
        for finding in framework_findings:
            severity = finding.get('severity', 'medium').upper()
            findings_by_severity[severity].append(finding)
        
        # Summary statistics
        summary_text = f"""
        <b>Total Framework Findings: {len(framework_findings)}</b><br/>
        <font color="#c0392b">● Critical: {len(findings_by_severity.get('CRITICAL', []))}</font><br/>
        <font color="#e67e22">● High: {len(findings_by_severity.get('HIGH', []))}</font><br/>
        <font color="#f39c12">● Medium: {len(findings_by_severity.get('MEDIUM', []))}</font><br/>
        <font color="#27ae60">● Low: {len(findings_by_severity.get('LOW', []))}</font><br/>
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Display findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            findings = findings_by_severity.get(severity, [])
            if not findings:
                continue
            
            # Severity header with color
            severity_colors = {
                'CRITICAL': '#c0392b',
                'HIGH': '#e67e22',
                'MEDIUM': '#f39c12',
                'LOW': '#27ae60',
                'INFO': '#3498db'
            }
            
            severity_icons = {
                'CRITICAL': '🔥',
                'HIGH': '⚠️',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': 'ℹ️'
            }
            
            color = severity_colors.get(severity, '#95a5a6')
            icon = severity_icons.get(severity, '●')
            
            self.story.append(Paragraph(
                f"<b><font color='{color}'>{icon} {severity} - {len(findings)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table for findings
            table_data = [['#', 'Issue', 'File', 'Type', 'Line']]
            
            for i, finding in enumerate(findings[:20], 1):  # Limit to 20 per severity
                issue = finding.get('issue', 'Unknown issue')[:50]
                file_name = os.path.basename(finding.get('file', 'Unknown'))[:25]
                finding_type = finding.get('type', 'N/A')[:15]
                line = str(finding.get('line', 'N/A'))
                
                table_data.append([
                    str(i),
                    issue,
                    file_name,
                    finding_type,
                    line
                ])
            
            # Create table
            findings_table = Table(table_data, colWidths=[0.3*inch, 2.8*inch, 1.6*inch, 1*inch, 0.5*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(color)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (4, 0), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white])
            ]
            
            findings_table.setStyle(TableStyle(table_style))
            self.story.append(findings_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Add recommendations for critical/high findings
            if severity in ['CRITICAL', 'HIGH']:
                recs_text = "<b>Key Recommendations:</b><br/>"
                seen_recs = set()
                
                for finding in findings[:5]:
                    rec = finding.get('recommendation', '')
                    if rec and rec not in seen_recs:
                        recs_text += f"• {rec[:100]}<br/>"
                        seen_recs.add(rec)
                
                if len(seen_recs) > 0:
                    self.story.append(Paragraph(recs_text, self.styles['Normal']))
                    self.story.append(Spacer(1, 0.1*inch))
        
        # Add framework detection summary
        frameworks_detected = set()
        for finding in framework_findings:
            issue = finding.get('issue', '')
            if 'Django' in issue:
                frameworks_detected.add('Django')
            elif 'Flask' in issue:
                frameworks_detected.add('Flask')
            elif 'FastAPI' in issue or 'Uvicorn' in issue:
                frameworks_detected.add('FastAPI')
            elif 'Express' in issue:
                frameworks_detected.add('Express.js')
            elif 'Node' in issue:
                frameworks_detected.add('Node.js')
            elif 'Spring' in issue:
                frameworks_detected.add('Spring Boot')
            elif 'ASP.NET' in issue or '.NET' in issue:
                frameworks_detected.add('ASP.NET')
        
        if frameworks_detected:
            self.story.append(Spacer(1, 0.2*inch))
            self.story.append(Paragraph(
                f"<b>Frameworks Detected:</b> {', '.join(sorted(frameworks_detected))}",
                self.styles['Normal']
            ))
        
        self.story.append(PageBreak())
    
    def add_cryptography_section(self, security_analysis):
        """Add cryptography misuse analysis section"""
        self.story.append(Paragraph("CRYPTOGRAPHY MISUSE ANALYSIS", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Collect all cryptography findings
        weak_hashing = []
        weak_encryption = []
        predictable_random = []
        unsalted_passwords = []
        ecb_mode = []
        jwt_issues = []
        all_crypto_findings = []
        
        # Handle both dict format and list format
        if isinstance(security_analysis, dict):
            for file_path, data in security_analysis.items():
                if isinstance(data, dict):
                    weak_hashing.extend(data.get("weak_hashing", []))
                    weak_encryption.extend(data.get("weak_encryption", []))
                    predictable_random.extend(data.get("predictable_random", []))
                    unsalted_passwords.extend(data.get("unsalted_passwords", []))
                    ecb_mode.extend(data.get("ecb_mode", []))
                    jwt_issues.extend(data.get("jwt_issues", []))
                    all_crypto_findings.extend(data.get("cryptography", []))
        elif isinstance(security_analysis, list):
            all_crypto_findings = security_analysis
        
        # If we got a flat list, categorize by type/message
        if all_crypto_findings and not (weak_hashing or weak_encryption):
            for finding in all_crypto_findings:
                finding_type = finding.get('type', finding.get('check_type', '')).lower()
                if 'hash' in finding_type or 'md5' in finding_type or 'sha1' in finding_type:
                    weak_hashing.append(finding)
                elif 'encryption' in finding_type or 'cipher' in finding_type:
                    weak_encryption.append(finding)
                elif 'random' in finding_type:
                    predictable_random.append(finding)
                elif 'password' in finding_type or 'salt' in finding_type:
                    unsalted_passwords.append(finding)
                elif 'ecb' in finding_type:
                    ecb_mode.append(finding)
                elif 'jwt' in finding_type:
                    jwt_issues.append(finding)
                else:
                    # Default to weak encryption
                    weak_encryption.append(finding)
        
        total_crypto_issues = (len(weak_hashing) + len(weak_encryption) + len(predictable_random) + 
                               len(unsalted_passwords) + len(ecb_mode) + len(jwt_issues))
        
        if total_crypto_issues == 0:
            self.story.append(Paragraph(
                "✓ No cryptography misuse issues detected.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        # Summary
        summary_text = f"""
        <b>Total Cryptography Issues: {total_crypto_issues}</b><br/>
        <font color="#c0392b">● Weak Encryption: {len(weak_encryption)}</font><br/>
        <font color="#c0392b">● ECB Mode: {len(ecb_mode)}</font><br/>
        <font color="#c0392b">● Unsalted Passwords: {len(unsalted_passwords)}</font><br/>
        <font color="#c0392b">● JWT Issues: {len(jwt_issues)}</font><br/>
        <font color="#e67e22">● Weak Hashing: {len(weak_hashing)}</font><br/>
        <font color="#e67e22">● Predictable Random: {len(predictable_random)}</font><br/>
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Create findings tables
        crypto_sections = [
            ("WEAK ENCRYPTION ALGORITHMS", weak_encryption, '#c0392b'),
            ("ECB MODE USAGE", ecb_mode, '#c0392b'),
            ("UNSALTED PASSWORD HASHING", unsalted_passwords, '#c0392b'),
            ("JWT SECURITY ISSUES", jwt_issues, '#c0392b'),
            ("WEAK HASHING ALGORITHMS", weak_hashing, '#e67e22'),
            ("PREDICTABLE RANDOM GENERATORS", predictable_random, '#e67e22'),
        ]
        
        for section_title, findings, color in crypto_sections:
            if not findings:
                continue
            
            self.story.append(Paragraph(
                f"<b><font color='{color}'>{section_title} - {len(findings)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'Issue', 'File', 'Line', 'Pattern']]
            
            for i, finding in enumerate(findings[:15], 1):  # Limit to 15
                message = finding.get('message', 'N/A')[:40]
                file_name = os.path.basename(finding.get('file', 'N/A'))[:20]
                line = str(finding.get('line', 'N/A'))
                pattern = finding.get('pattern', 'N/A')[:25]
                
                table_data.append([
                    str(i),
                    message,
                    file_name,
                    line,
                    pattern
                ])
            
            # Create table
            crypto_table = Table(table_data, colWidths=[0.3*inch, 2.2*inch, 1.5*inch, 0.5*inch, 1.7*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(color)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white])
            ]
            
            crypto_table.setStyle(TableStyle(table_style))
            self.story.append(crypto_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Add recommendations
            if findings:
                recs_text = "<b>Recommendations:</b><br/>"
                seen_recs = set()
                
                for finding in findings[:3]:
                    rec = finding.get('recommendation', '')
                    if rec and rec not in seen_recs:
                        recs_text += f"• {rec[:90]}<br/>"
                        seen_recs.add(rec)
                
                if len(seen_recs) > 0:
                    self.story.append(Paragraph(recs_text, self.styles['Normal']))
                    self.story.append(Spacer(1, 0.1*inch))
        
        self.story.append(PageBreak())
    
    def add_authentication_section(self, security_analysis):
        """Add authentication and session security analysis section"""
        self.story.append(Paragraph("AUTHENTICATION & SESSION SECURITY", self.styles['SectionHeader']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Collect all authentication findings
        weak_session = []
        missing_rotation = []
        cookie_flags = []
        missing_mfa = []
        weak_password = []
        auth_bypass = []
        all_auth_findings = []
        
        # Handle both dict format and list format
        if isinstance(security_analysis, dict):
            for file_path, data in security_analysis.items():
                if isinstance(data, dict):
                    weak_session.extend(data.get("weak_session_timeout", []))
                    missing_rotation.extend(data.get("missing_session_rotation", []))
                    cookie_flags.extend(data.get("insecure_cookie_flags", []))
                    missing_mfa.extend(data.get("missing_mfa", []))
                    weak_password.extend(data.get("weak_password_policy", []))
                    auth_bypass.extend(data.get("auth_bypass", []))
                    all_auth_findings.extend(data.get("authentication", []))
        elif isinstance(security_analysis, list):
            all_auth_findings = security_analysis
        
        # If we got a flat list, categorize by type/message
        if all_auth_findings and not (weak_session or missing_rotation or cookie_flags):
            print(f"[PDF AUTH] Categorizing {len(all_auth_findings)} findings...")
            for i, finding in enumerate(all_auth_findings):
                finding_type = finding.get('type', finding.get('check_type', '')).lower()
                finding_msg = finding.get('message', finding.get('description', '')).lower()
                if i < 2:  # Debug first 2
                    print(f"[PDF AUTH] Finding {i+1}: type='{finding_type}', msg='{finding_msg[:50]}'...")
                    
                # Check both type and message for categorization
                combined = finding_type + ' ' + finding_msg
                
                if 'session' in combined and 'timeout' in combined:
                    weak_session.append(finding)
                elif 'rotation' in combined:
                    missing_rotation.append(finding)
                elif 'cookie' in combined:
                    cookie_flags.append(finding)
                elif 'mfa' in combined or 'multi-factor' in combined:
                    missing_mfa.append(finding)
                elif 'password' in combined:
                    weak_password.append(finding)
                elif 'bypass' in combined or 'authentication' in combined:
                    auth_bypass.append(finding)
                else:
                    # Default to weak session
                    weak_session.append(finding)
            
            print(f"[PDF AUTH] Categorized: session={len(weak_session)}, rotation={len(missing_rotation)}, cookies={len(cookie_flags)}, mfa={len(missing_mfa)}, password={len(weak_password)}, bypass={len(auth_bypass)}")
        
        total_auth_issues = (len(weak_session) + len(missing_rotation) + len(cookie_flags) + 
                            len(missing_mfa) + len(weak_password) + len(auth_bypass))
        
        if total_auth_issues == 0:
            self.story.append(Paragraph(
                "✓ No authentication or session security issues detected.",
                self.styles['Normal']
            ))
            self.story.append(Spacer(1, 0.3*inch))
            return
        
        # Summary
        summary_text = f"""
        <b>Total Authentication & Session Issues: {total_auth_issues}</b><br/>
        <font color="#c0392b">● Auth Bypass: {len(auth_bypass)}</font><br/>
        <font color="#e67e22">● Insecure Cookies: {len(cookie_flags)}</font><br/>
        <font color="#f39c12">● Weak Session Timeout: {len(weak_session)}</font><br/>
        <font color="#f39c12">● Missing Session Rotation: {len(missing_rotation)}</font><br/>
        <font color="#f39c12">● Missing MFA: {len(missing_mfa)}</font><br/>
        <font color="#3498db">● Weak Password Policy: {len(weak_password)}</font><br/>
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Create findings tables
        auth_sections = [
            ("AUTHENTICATION BYPASS", auth_bypass, '#c0392b'),
            ("INSECURE COOKIE FLAGS", cookie_flags, '#e67e22'),
            ("WEAK SESSION TIMEOUT", weak_session, '#f39c12'),
            ("MISSING SESSION ROTATION", missing_rotation, '#f39c12'),
            ("MISSING MULTI-FACTOR AUTHENTICATION", missing_mfa, '#f39c12'),
            ("WEAK PASSWORD POLICY", weak_password, '#3498db'),
        ]
        
        for section_title, findings, color in auth_sections:
            if not findings:
                continue
            
            self.story.append(Paragraph(
                f"<b><font color='{color}'>{section_title} - {len(findings)} findings</font></b>",
                self.styles['Heading3']
            ))
            self.story.append(Spacer(1, 0.1*inch))
            
            # Create table
            table_data = [['#', 'Issue', 'File', 'Line', 'Type']]
            
            for i, finding in enumerate(findings[:15], 1):  # Limit to 15
                message = finding.get('message', 'N/A')[:45]
                file_name = os.path.basename(finding.get('file', 'N/A'))[:20]
                line = str(finding.get('line', 'N/A'))
                finding_type = finding.get('type', 'N/A')[:20]
                
                table_data.append([
                    str(i),
                    message,
                    file_name,
                    line,
                    finding_type
                ])
            
            # Create table
            auth_table = Table(table_data, colWidths=[0.3*inch, 2.5*inch, 1.5*inch, 0.5*inch, 1.4*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(color)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white])
            ]
            
            auth_table.setStyle(TableStyle(table_style))
            self.story.append(auth_table)
            self.story.append(Spacer(1, 0.15*inch))
            
            # Add recommendations
            if findings:
                recs_text = "<b>Recommendations:</b><br/>"
                seen_recs = set()
                
                for finding in findings[:3]:
                    rec = finding.get('recommendation', '')
                    if rec and rec not in seen_recs:
                        recs_text += f"• {rec[:85]}<br/>"
                        seen_recs.add(rec)
                
                if len(seen_recs) > 0:
                    self.story.append(Paragraph(recs_text, self.styles['Normal']))
                    self.story.append(Spacer(1, 0.1*inch))
        
        self.story.append(PageBreak())
    
    def generate(self, analysis_result, project_name=""):
        """Generate the complete PDF report with enhanced sections"""
        from utils.enhanced_analysis import (
            generate_file_tree, deduplicate_findings,
            generate_intelligent_findings_table, generate_data_flow_diagram
        )
        
        # Title page
        self.add_title_page(project_name)
        
        # Executive summary
        self.add_executive_summary(
            analysis_result.get('risk_assessment', {}),
            analysis_result.get('project_languages', [])
        )
        
        # File tree hierarchy with enhanced formatting
        try:
            file_tree = generate_file_tree(".", analysis_result.get('security_analysis', {}))
            self.add_file_tree_section(file_tree, analysis_result.get('security_analysis', {}))
        except Exception as e:
            print(f"[!] Warning: Could not generate file tree: {e}")
        
        # Intelligent findings table with beautiful formatting
        try:
            deduplicated = deduplicate_findings(analysis_result.get('security_analysis', {}))
            self.add_findings_table_section(deduplicated)
        except Exception as e:
            print(f"[!] Warning: Could not generate findings table: {e}")
        
        # Dangerous functions
        self.add_dangerous_functions_section(
            analysis_result.get('security_analysis', {})
        )
        
        # Taint flows
        self.add_taint_flows_section(
            analysis_result.get('taint_flows', [])
        )
        
        # Secrets
        self.add_secrets_section(
            analysis_result.get('security_analysis', {})
        )
        
        # Framework-specific security findings (NEW)
        print("[PDF] Adding Framework Security section...")
        framework_data = analysis_result.get('framework_security_findings', [])
        print(f"[PDF]   Framework data: {len(framework_data) if isinstance(framework_data, list) else 'dict'} items")
        self.add_framework_findings_section(framework_data)
        
        # Cryptography misuse analysis (NEW)
        print("[PDF] Adding Cryptography section...")
        crypto_data = analysis_result.get('cryptography', analysis_result.get('security_analysis', {}))
        print(f"[PDF]   Crypto data type: {type(crypto_data)}, items: {len(crypto_data) if isinstance(crypto_data, (list, dict)) else 0}")
        self.add_cryptography_section(crypto_data)
        
        # Authentication & session security analysis (NEW)
        print("[PDF] Adding Authentication section...")
        auth_data = analysis_result.get('authentication', analysis_result.get('security_analysis', {}))
        print(f"[PDF]   Auth data type: {type(auth_data)}, items: {len(auth_data) if isinstance(auth_data, (list, dict)) else 0}")
        self.add_authentication_section(auth_data)
        
        # Code Quality & Maintainability Analysis (NEW)
        print("[PDF] Adding Quality section...")
        quality_data = analysis_result.get('quality_analysis', {})
        print(f"[PDF]   Quality data: {quality_data.get('summary', {})}")
        self.add_quality_findings_section(quality_data)
        
        # Anti-Pattern & Security Issues Detection (NEW)
        print("[PDF] Adding Anti-Pattern section...")
        antipattern_data = analysis_result.get('antipattern_analysis', {})
        print(f"[PDF]   Antipattern data: {antipattern_data.get('summary', {})}")
        self.add_antipattern_findings_section(antipattern_data)
        
        # Dependency Vulnerability Analysis (NEW)
        print("[PDF] Adding Vulnerability Scan section...")
        vuln_scan_data = analysis_result.get('vulnerability_scan', {})
        print(f"[PDF]   Vuln scan data: {len(vuln_scan_data.get('packages', []))} vulnerable packages")
        self.add_vulnerability_scan_section(vuln_scan_data)
        
        # Recommendations
        self.add_recommendations_section()
        
        # Build PDF
        self.doc.build(self.story, onFirstPage=self.add_footer, onLaterPages=self.add_footer)
        
        return self.filename


