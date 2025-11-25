// PDF Export Utility with Cyber-Security Theme
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { AnalysisResult, ReportConfig } from '../types';
import { theme } from '../styles/theme';
import { formatDate, getSeverityColor } from './helpers';

// Theme colors for PDF (RGB values) - Using lighter background for better readability
const pdfColors = {
  background: { r: 20, g: 30, b: 45 }, // Lighter dark blue for readability
  cardBg: { r: 30, g: 42, b: 58 }, // Slightly lighter card background
  primary: { r: 18, g: 226, b: 240 }, // #12e2f0 (cyan)
  accent: { r: 0, g: 255, b: 154 }, // #00ff9a (green)
  text: { r: 240, g: 245, b: 250 }, // Brighter text for visibility
  textSecondary: { r: 200, g: 210, b: 225 }, // Lighter secondary text
  critical: { r: 255, g: 59, b: 59 }, // #ff3b3b
  high: { r: 255, g: 107, b: 53 }, // #ff6b35
  medium: { r: 251, g: 191, b: 36 }, // #fbbf24
  low: { r: 0, g: 255, b: 154 }, // Brighter green
};

// Helper: Clean text to prevent encoding issues
const cleanText = (text: string): string => {
  if (!text) return '';
  return text
    .toString()
    .replace(/[^\x00-\x7F]/g, '') // Remove non-ASCII characters
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove control characters
    .replace(/\s+/g, ' ') // Normalize whitespace
    .trim()
    .substring(0, 500); // Limit length
};

export const exportToPDF = async (
  analysisData: AnalysisResult,
  config: ReportConfig
): Promise<void> => {
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  let yPosition = margin;

  // Helper: Add new page if needed
  const checkAndAddPage = (requiredSpace: number = 20) => {
    if (yPosition + requiredSpace > pageHeight - margin - 15) {
      addNewPage();
      return true;
    }
    return false;
  };

  // Helper: Add new page with consistent background
  const addNewPage = () => {
    doc.addPage();
    drawBackground();
    yPosition = margin;
  };

  // Helper: Draw gradient-like background on every page
  const drawBackground = () => {
    doc.setFillColor(pdfColors.background.r, pdfColors.background.g, pdfColors.background.b);
    doc.rect(0, 0, pageWidth, pageHeight, 'F');
  };

  // Helper: Add section header
  const addSectionHeader = (title: string, icon: string) => {
    checkAndAddPage(30);
    
    const cleanedTitle = cleanText(title);
    
    // Background box for header
    doc.setFillColor(pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b);
    doc.roundedRect(margin, yPosition, pageWidth - 2 * margin, 12, 2, 2, 'F');
    
    // Cyan border
    doc.setDrawColor(pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, yPosition, pageWidth - 2 * margin, 12, 2, 2, 'S');
    
    // Icon and title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b);
    doc.text(`${icon} ${cleanedTitle}`, margin + 5, yPosition + 8);
    
    yPosition += 17;
    resetTextStyle();
  };

  // Helper: Reset text style to default
  const resetTextStyle = () => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(11);
    doc.setTextColor(pdfColors.textSecondary.r, pdfColors.textSecondary.g, pdfColors.textSecondary.b);
  };

  // Helper: Add text with color
  const addText = (text: string, fontSize: number = 11, color: 'primary' | 'secondary' | 'accent' = 'secondary', bold: boolean = false) => {
    checkAndAddPage(fontSize * 2);
    
    const cleanedText = cleanText(text);
    if (!cleanedText) return;
    
    doc.setFont('helvetica', bold ? 'bold' : 'normal');
    doc.setFontSize(fontSize);
    
    const colorMap = {
      primary: pdfColors.text,
      secondary: pdfColors.textSecondary,
      accent: pdfColors.accent,
    };
    
    const c = colorMap[color];
    doc.setTextColor(c.r, c.g, c.b);
    
    const lines = doc.splitTextToSize(cleanedText, pageWidth - 2 * margin - 10);
    lines.forEach((line: string) => {
      checkAndAddPage(fontSize * 1.5);
      doc.text(line, margin + 5, yPosition);
      yPosition += fontSize * 0.45;
    });
    yPosition += 4;
    resetTextStyle();
  };

  // Helper: Get severity color
  const getSeverityColorRGB = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return pdfColors.critical;
      case 'HIGH':
        return pdfColors.high;
      case 'MEDIUM':
        return pdfColors.medium;
      case 'LOW':
        return pdfColors.low;
      default:
        return pdfColors.textSecondary;
    }
  };

  // Helper: Add badge
  const addBadge = (text: string, x: number, y: number, severity?: string) => {
    const color = severity ? getSeverityColorRGB(severity) : pdfColors.accent;
    doc.setFillColor(color.r, color.g, color.b, 0.2);
    doc.setDrawColor(color.r, color.g, color.b);
    doc.roundedRect(x, y - 4, 25, 6, 1, 1, 'FD');
    doc.setTextColor(color.r, color.g, color.b);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.text(text, x + 2, y);
  };

  // Helper: Add code snippet
  const addCodeSnippet = (code: string, title?: string) => {
    checkAndAddPage(35);
    
    const cleanedCode = cleanText(code || '// No code available');
    
    if (title) {
      const cleanedTitle = cleanText(title);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(pdfColors.accent.r, pdfColors.accent.g, pdfColors.accent.b);
      doc.text(cleanedTitle, margin + 5, yPosition);
      yPosition += 6;
    }
    
    // Code box
    doc.setFillColor(pdfColors.background.r, pdfColors.background.g, pdfColors.background.b);
    const codeLines = cleanedCode.split('\n').slice(0, 8); // Limit lines
    const codeHeight = Math.min(codeLines.length * 4 + 4, 40);
    
    checkAndAddPage(codeHeight + 10);
    
    doc.roundedRect(margin, yPosition, pageWidth - 2 * margin, codeHeight, 2, 2, 'F');
    
    doc.setDrawColor(pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b, 0.3);
    doc.setLineWidth(0.3);
    doc.roundedRect(margin, yPosition, pageWidth - 2 * margin, codeHeight, 2, 2, 'S');
    
    // Code text
    doc.setFont('courier', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(pdfColors.accent.r, pdfColors.accent.g, pdfColors.accent.b);
    
    codeLines.forEach((line, index) => {
      if (yPosition + (index + 1) * 4 < yPosition + codeHeight - 2) {
        const cleanedLine = cleanText(line).substring(0, 90);
        doc.text(cleanedLine, margin + 3, yPosition + 4 + index * 4);
      }
    });
    
    yPosition += codeHeight + 7;
    resetTextStyle();
  };

  // ============================================
  // START PDF GENERATION
  // ============================================

  drawBackground();

  // ============================================
  // COVER PAGE
  // ============================================
  
  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(32);
  doc.setTextColor(pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b);
  doc.text('🛡️', pageWidth / 2 - 10, 60);
  doc.text('CodeX Security', pageWidth / 2, 75, { align: 'center' });
  doc.text('Analysis Report', pageWidth / 2, 90, { align: 'center' });
  
  // Subtitle
  doc.setFontSize(14);
  doc.setTextColor(pdfColors.accent.r, pdfColors.accent.g, pdfColors.accent.b);
  doc.text('Comprehensive Code Security Assessment', pageWidth / 2, 105, { align: 'center' });
  
  // Project info box
  doc.setFillColor(pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b);
  doc.roundedRect(30, 120, pageWidth - 60, 40, 3, 3, 'F');
  doc.setDrawColor(pdfColors.accent.r, pdfColors.accent.g, pdfColors.accent.b);
  doc.setLineWidth(1);
  doc.roundedRect(30, 120, pageWidth - 60, 40, 3, 3, 'S');
  
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(11);
  doc.setTextColor(pdfColors.text.r, pdfColors.text.g, pdfColors.text.b);
  
  const projectPath = cleanText(analysisData.metadata.project_path || 'Unknown');
  const scanDate = cleanText(formatDate(analysisData.metadata.scan_time));
  
  doc.text(`Project: ${projectPath}`, 35, 130);
  doc.text(`Scan Date: ${scanDate}`, 35, 138);
  doc.text(`Total Files: ${analysisData.summary.files_scanned}`, 35, 146);
  doc.text(`Total Issues: ${analysisData.summary.total_issues}`, 35, 154);
  
  // Risk level badge
  const riskColor = getSeverityColorRGB(analysisData.summary.risk_level);
  doc.setFillColor(riskColor.r, riskColor.g, riskColor.b, 0.2);
  doc.setDrawColor(riskColor.r, riskColor.g, riskColor.b);
  doc.roundedRect(pageWidth / 2 - 30, 170, 60, 15, 3, 3, 'FD');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(riskColor.r, riskColor.g, riskColor.b);
  doc.text(`RISK: ${analysisData.summary.risk_level}`, pageWidth / 2, 180, { align: 'center' });
  
  // Footer
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(pdfColors.textSecondary.r, pdfColors.textSecondary.g, pdfColors.textSecondary.b);
  doc.text('Generated by CodeX Analysis Platform', pageWidth / 2, pageHeight - 20, { align: 'center' });
  doc.text('Enterprise Security Code Analysis', pageWidth / 2, pageHeight - 15, { align: 'center' });

  // ============================================
  // EXECUTIVE SUMMARY
  // ============================================
  if (config.selectedSections.executiveSummary) {
    addNewPage();
    
    addSectionHeader('Executive Summary', '📊');
    
    addText('This report provides a comprehensive security analysis of your codebase, identifying vulnerabilities, dangerous functions, and security issues.', 11, 'secondary');
    yPosition += 5;
    
    // Summary stats table
    const summaryData = [
      ['Dangerous Functions', analysisData.summary.dangerous_functions_count.toString()],
      ['Secrets Detected', analysisData.summary.secrets_count.toString()],
      ['Validation Issues', analysisData.summary.validation_issues_count.toString()],
      ['Crypto Issues', analysisData.summary.crypto_issues_count.toString()],
      ['Auth Issues', analysisData.summary.auth_issues_count.toString()],
      ['Framework Issues', analysisData.summary.framework_issues_count.toString()],
      ['Anti-Patterns', analysisData.summary.antipattern_count.toString()],
      ['Vulnerabilities', analysisData.summary.vulnerability_count.toString()],
    ];
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Category', 'Count']],
      body: summaryData,
      theme: 'plain',
      styles: {
        fillColor: [pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b],
        textColor: [pdfColors.text.r, pdfColors.text.g, pdfColors.text.b],
        fontSize: 10,
        cellPadding: 5,
        font: 'helvetica',
        fontStyle: 'normal',
        lineColor: [pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b],
        lineWidth: 0.1,
      },
      headStyles: {
        fillColor: [pdfColors.primary.r, pdfColors.primary.g, pdfColors.primary.b],
        textColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
        fontStyle: 'bold',
        fontSize: 11,
      },
      alternateRowStyles: {
        fillColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
      },
      didDrawPage: () => {
        drawBackground();
      },
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
    resetTextStyle();
  }

  // ============================================
  // DANGEROUS FUNCTIONS
  // ============================================
  if (config.selectedSections.dangerousFunctions && analysisData.dangerous_functions.length > 0) {
    checkAndAddPage(40);
    addSectionHeader('Dangerous Functions', '⚠️');
    
    addText(`Found ${analysisData.dangerous_functions.length} dangerous function calls that could pose security risks.`, 11, 'secondary');
    yPosition += 5;
    
    const dangerousData = analysisData.dangerous_functions.slice(0, 20).map(item => [
      cleanText(item.function || ''),
      cleanText(item.category || ''),
      cleanText(item.file.split('\\').pop()?.substring(0, 30) || ''),
      item.line?.toString() || '0',
    ]);
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Function', 'Category', 'File', 'Line']],
      body: dangerousData,
      theme: 'plain',
      styles: {
        fillColor: [pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b],
        textColor: [pdfColors.text.r, pdfColors.text.g, pdfColors.text.b],
        fontSize: 9,
        cellPadding: 4,
        font: 'helvetica',
        fontStyle: 'normal',
        lineColor: [pdfColors.high.r, pdfColors.high.g, pdfColors.high.b],
        lineWidth: 0.1,
      },
      headStyles: {
        fillColor: [pdfColors.high.r, pdfColors.high.g, pdfColors.high.b],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 10,
      },
      columnStyles: {
        0: { textColor: [pdfColors.accent.r, pdfColors.accent.g, pdfColors.accent.b], fontStyle: 'bold' },
      },
      alternateRowStyles: {
        fillColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
      },
      didDrawPage: () => {
        drawBackground();
      },
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
    resetTextStyle();
    
    if (config.includeCodeSnippets && analysisData.dangerous_functions[0]) {
      addText('Example:', 10, 'accent', true);
      addCodeSnippet(analysisData.dangerous_functions[0].context, analysisData.dangerous_functions[0].function);
    }
  }

  // ============================================
  // SECRETS
  // ============================================
  if (config.selectedSections.secrets && analysisData.secrets.length > 0) {
    checkAndAddPage(40);
    addSectionHeader('Hardcoded Secrets', '🔑');
    
    addText(`Found ${analysisData.secrets.length} hardcoded secrets or credentials in your codebase.`, 11, 'secondary');
    yPosition += 5;
    
    const secretsData = analysisData.secrets.slice(0, 15).map(item => [
      cleanText(item.type || ''),
      cleanText(item.file.split('\\').pop()?.substring(0, 35) || ''),
      item.line?.toString() || '0',
      cleanText(item.severity || 'UNKNOWN'),
    ]);
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Type', 'File', 'Line', 'Severity']],
      body: secretsData,
      theme: 'plain',
      styles: {
        fillColor: [pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b],
        textColor: [pdfColors.text.r, pdfColors.text.g, pdfColors.text.b],
        fontSize: 9,
        cellPadding: 4,
        font: 'helvetica',
        fontStyle: 'normal',
        lineColor: [pdfColors.critical.r, pdfColors.critical.g, pdfColors.critical.b],
        lineWidth: 0.1,
      },
      headStyles: {
        fillColor: [pdfColors.critical.r, pdfColors.critical.g, pdfColors.critical.b],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 10,
      },
      alternateRowStyles: {
        fillColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
      },
      didDrawCell: (data: any) => {
        if (data.column.index === 3 && data.section === 'body') {
          const severity = data.cell.raw;
          const color = getSeverityColorRGB(severity);
          doc.setTextColor(color.r, color.g, color.b);
        }
      },
      didDrawPage: () => {
        drawBackground();
      },
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
    resetTextStyle();
  }

  // ============================================
  // VALIDATION ISSUES
  // ============================================
  if (config.selectedSections.validationIssues && analysisData.validation_issues.length > 0) {
    checkAndAddPage(40);
    addSectionHeader('Validation Issues', '🛡️');
    
    addText(`Found ${analysisData.validation_issues.length} input validation issues.`, 11, 'secondary');
    yPosition += 5;
    
    const validationData = analysisData.validation_issues.slice(0, 15).map(item => [
      cleanText(item.type?.substring(0, 25) || ''),
      cleanText(item.file.split('\\').pop()?.substring(0, 30) || ''),
      cleanText(item.severity || 'UNKNOWN'),
      cleanText(item.message?.substring(0, 40) || ''),
    ]);
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Type', 'File', 'Severity', 'Message']],
      body: validationData,
      theme: 'plain',
      styles: {
        fillColor: [pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b],
        textColor: [pdfColors.text.r, pdfColors.text.g, pdfColors.text.b],
        fontSize: 8,
        cellPadding: 3,
        font: 'helvetica',
        fontStyle: 'normal',
        lineColor: [pdfColors.medium.r, pdfColors.medium.g, pdfColors.medium.b],
        lineWidth: 0.1,
      },
      headStyles: {
        fillColor: [pdfColors.medium.r, pdfColors.medium.g, pdfColors.medium.b],
        textColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
        fontStyle: 'bold',
        fontSize: 9,
      },
      alternateRowStyles: {
        fillColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
      },
      didDrawPage: () => {
        drawBackground();
      },
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
    resetTextStyle();
  }

  // ============================================
  // AUTHENTICATION ISSUES
  // ============================================
  if (config.selectedSections.authIssues && analysisData.auth_issues.length > 0) {
    checkAndAddPage(40);
    addSectionHeader('Authentication Issues', '🔐');
    
    addText(`Found ${analysisData.auth_issues.length} authentication and session management issues.`, 11, 'secondary');
    yPosition += 5;
    
    const authData = analysisData.auth_issues.slice(0, 15).map(item => [
      cleanText(item.type?.substring(0, 30) || ''),
      cleanText(item.file.split('\\').pop()?.substring(0, 30) || ''),
      cleanText(item.severity || 'UNKNOWN'),
    ]);
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Issue Type', 'File', 'Severity']],
      body: authData,
      theme: 'plain',
      styles: {
        fillColor: [pdfColors.cardBg.r, pdfColors.cardBg.g, pdfColors.cardBg.b],
        textColor: [pdfColors.text.r, pdfColors.text.g, pdfColors.text.b],
        fontSize: 9,
        cellPadding: 4,
        font: 'helvetica',
        fontStyle: 'normal',
        lineColor: [pdfColors.high.r, pdfColors.high.g, pdfColors.high.b],
        lineWidth: 0.1,
      },
      headStyles: {
        fillColor: [pdfColors.high.r, pdfColors.high.g, pdfColors.high.b],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 10,
      },
      alternateRowStyles: {
        fillColor: [pdfColors.background.r, pdfColors.background.g, pdfColors.background.b],
      },
      didDrawPage: () => {
        drawBackground();
      },
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
    resetTextStyle();
  }

  // ============================================
  // RECOMMENDATIONS
  // ============================================
  if (config.includeRecommendations) {
    checkAndAddPage(40);
    addSectionHeader('Recommendations', '✅');
    
    addText('Priority Actions:', 11, 'accent', true);
    yPosition += 3;
    
    const recommendations = [
      '1. Address all CRITICAL severity issues immediately',
      '2. Remove hardcoded secrets and use environment variables',
      '3. Implement input validation for all user inputs',
      '4. Replace dangerous functions with safe alternatives',
      '5. Enable multi-factor authentication where applicable',
      '6. Update vulnerable dependencies',
      '7. Implement proper error handling',
      '8. Add security testing to your CI/CD pipeline',
    ];
    
    recommendations.forEach(rec => {
      addText(rec, 10, 'secondary');
    });
  }

  // ============================================
  // FOOTER ON EVERY PAGE
  // ============================================
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    
    // Footer text with consistent styling
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(pdfColors.textSecondary.r, pdfColors.textSecondary.g, pdfColors.textSecondary.b);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 10, { align: 'right' });
    doc.text('CodeX Security Analysis', margin, pageHeight - 10);
  }

  // ============================================
  // SAVE PDF
  // ============================================
  const filename = `security-analysis-${Date.now()}.pdf`;
  doc.save(filename);
};

