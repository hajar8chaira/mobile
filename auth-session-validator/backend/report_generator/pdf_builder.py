"""
report_generator/pdf_builder.py
─────────────────────────────────
Générateur de rapport PDF professionnel.
Basé sur ReportLab. Inclut : résumé exécutif, findings détaillés, preuves, recommandations.
"""

from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit


class PDFReportBuilder:
    """
    Construit un rapport PDF complet à partir des résultats d'analyse.
    """

    def __init__(self, output_path: str):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Configure les styles personnalisés pour le rapport."""
        # Style pour les titres de sections
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue,
            spaceBefore=12
        ))

        # Style pour les sous-titres
        self.styles.add(ParagraphStyle(
            name='SubsectionTitle',
            parent=self.styles['Heading2'],
            fontSize=12,
            spaceAfter=6,
            textColor=colors.darkblue,
            spaceBefore=6
        ))

        # Style pour le texte de preuve
        self.styles.add(ParagraphStyle(
            name='ProofText',
            parent=self.styles['Code'],
            fontSize=8,
            leftIndent=20,
            spaceAfter=6,
            backColor=colors.lightgrey,
            borderPadding=5
        ))

        # Style pour les badges de sévérité
        self.styles.add(ParagraphStyle(
            name='SeverityBadge',
            parent=self.styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER
        ))

    def build(self, report_data: Dict[str, Any]) -> str:
        """
        Génère un rapport PDF complet.

        Structure du rapport :
        1. Page de couverture (app name, date, score global, grade)
        2. Résumé exécutif (tableau des findings par severity)
        3. Module 1 — Analyse Statique (secrets, permissions, endpoints)
        4. Module 2 — Analyse Dynamique (trafic HTTP, JWT interceptés)
        5. Module 3 — Validations Actives (chaque test avec preuve)
        6. Module 4 — Corrélations (statique ↔ dynamique)
        7. Recommandations de remédiation
        8. Annexes (tokens bruts, logs de proxy)

        Args:
            report_data: Résultat complet de l'analyse (statique + dynamique + actif + corrélation)

        Returns:
            Chemin vers le fichier PDF généré
        """
        # Créer un document ReportLab (SimpleDocTemplate)
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        # Définir les styles (couleurs par severity, polices)
        story = []

        # Construire chaque section avec les données
        # Page de couverture
        story.extend(self._build_cover_page(
            report_data.get("app_name", "Unknown Application"),
            report_data.get("risk_score", 0),
            report_data.get("grade", "N/A")
        ))

        story.append(PageBreak())

        # Résumé exécutif
        story.extend(self._build_executive_summary(
            report_data.get("findings_summary", {})
        ))

        story.append(PageBreak())

        # Findings détaillés
        findings = report_data.get("findings", [])
        for finding in findings:
            story.extend(self._build_finding_section(finding))
            story.append(Spacer(1, 12))

        story.append(PageBreak())

        # Recommandations
        story.extend(self._build_recommendations())

        # Sauvegarder et retourner le chemin
        doc.build(story)
        return self.output_path

    def _build_cover_page(self, app_name: str, score: int, grade: str) -> list:
        """Construit la page de couverture avec le score visuel."""
        elements = []

        # Logo, titre, date, score, grade, risk_label
        elements.append(Spacer(1, 2*inch))

        # Titre principal
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30,
            textColor=colors.darkblue
        )

        elements.append(Paragraph("Security Audit Report", title_style))
        elements.append(Spacer(1, 0.5*inch))

        # Nom de l'application
        app_style = ParagraphStyle(
            'AppName',
            parent=self.styles['Heading2'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20
        )
        elements.append(Paragraph(f"Application: {app_name}", app_style))

        # Score et grade
        from datetime import datetime
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        score_data = [
            ['Metric', 'Value'],
            ['Risk Score', str(score)],
            ['Security Grade', grade],
            ['Audit Date', date_str]
        ]

        score_table = Table(score_data, colWidths=[2*inch, 2*inch], hAlign='CENTER')
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(score_table)
        elements.append(Spacer(1, 1*inch))

        # Disclaimer
        disclaimer_style = ParagraphStyle(
            'Disclaimer',
            parent=self.styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.grey
        )
        elements.append(Paragraph(
            "This report contains sensitive security information. "
            "Handle with care and share only with authorized personnel.",
            disclaimer_style
        ))

        return elements

    def _build_executive_summary(self, findings_summary: dict) -> list:
        """Construit le résumé exécutif avec tableau de findings."""
        elements = []

        # Titre de section
        elements.append(Paragraph("Executive Summary", self.styles['SectionTitle']))
        elements.append(Spacer(1, 12))

        # Tableau CRITICAL/HIGH/MEDIUM/LOW avec comptages
        severity_data = [['Severity', 'Count', 'Risk Level']]

        severity_colors = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.yellow,
            'LOW': colors.green,
            'INFO': colors.blue
        }

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = findings_summary.get(severity.lower(), 0)
            risk_level = self._get_risk_description(severity)
            severity_data.append([severity, str(count), risk_level])

        summary_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        # Colorer les lignes selon la sévérité
        for i, severity in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], 1):
            if severity in severity_colors:
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, i), (-1, i), severity_colors[severity])
                ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 12))

        # Graphique en secteurs (ou barre de score)
        total_findings = sum(findings_summary.values())
        if total_findings > 0:
            elements.append(Paragraph(
                f"Total Findings: {total_findings}",
                self.styles['SubsectionTitle']
            ))

        return elements

    def _build_finding_section(self, finding: dict) -> list:
        """Construit la section d'un finding individuel avec preuve."""
        elements = []

        # Titre du finding, severity badge, description
        title = finding.get("title", "Unknown Finding")
        severity = finding.get("severity", "INFO")
        description = finding.get("description", "")

        # Créer un titre coloré selon la sévérité
        severity_colors = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.yellow,
            'LOW': colors.green,
            'INFO': colors.blue
        }

        title_color = severity_colors.get(severity, colors.black)

        title_style = ParagraphStyle(
            'FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=title_color,
            spaceAfter=6
        )

        elements.append(Paragraph(f"[{severity}] {title}", title_style))
        elements.append(Paragraph(description, self.styles['Normal']))
        elements.append(Spacer(1, 6))

        # Evidence / proof (code block ou HTTP request/response)
        evidence = finding.get("evidence", "")
        if evidence:
            elements.append(Paragraph("Evidence:", self.styles['SubsectionTitle']))
            elements.append(Paragraph(evidence, self.styles['ProofText']))
            elements.append(Spacer(1, 6))

        # Recommandation de remédiation
        remediation = finding.get("remediation", "")
        if remediation:
            elements.append(Paragraph("Remediation:", self.styles['SubsectionTitle']))
            elements.append(Paragraph(remediation, self.styles['Normal']))
            elements.append(Spacer(1, 6))

        # Vecteur CVSS
        cvss_vector = finding.get("cvss_vector", "")
        if cvss_vector:
            elements.append(Paragraph(f"CVSS Vector: {cvss_vector}", self.styles['Normal']))
            elements.append(Spacer(1, 6))

        return elements

    def _build_recommendations(self) -> list:
        """Construit la section des recommandations générales."""
        elements = []

        # Liste des recommandations OWASP Mobile Top 10
        elements.append(Paragraph("Security Recommendations", self.styles['SectionTitle']))
        elements.append(Spacer(1, 12))

        recommendations = [
            "1. Implement proper certificate pinning to prevent MITM attacks",
            "2. Use strong encryption for sensitive data storage (AES-256-GCM)",
            "3. Implement proper session management with secure token handling",
            "4. Validate and sanitize all user inputs to prevent injection attacks",
            "5. Use secure communication protocols (HTTPS only)",
            "6. Implement proper authentication and authorization mechanisms",
            "7. Regularly update dependencies and security patches",
            "8. Implement proper logging and monitoring for security events",
            "9. Conduct regular security audits and penetration testing",
            "10. Follow OWASP Mobile Security Testing Guide"
        ]

        for recommendation in recommendations:
            elements.append(Paragraph(recommendation, self.styles['Normal']))
            elements.append(Spacer(1, 6))

        return elements

    def _get_risk_description(self, severity: str) -> str:
        """Retourne une description du niveau de risque."""
        risk_descriptions = {
            'CRITICAL': 'Immediate action required',
            'HIGH': 'High priority - fix soon',
            'MEDIUM': 'Medium priority - plan fix',
            'LOW': 'Low priority - consider fix',
            'INFO': 'Informational - no action required'
        }
        return risk_descriptions.get(severity, 'Unknown')
