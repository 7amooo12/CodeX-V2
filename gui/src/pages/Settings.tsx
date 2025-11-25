import React, { useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Button, Badge } from '../components/common';
import { theme } from '../styles/theme';
import { exportToPDF } from '../utils/pdfExport';
import { exportToJSON } from '../utils/helpers';

const Settings: React.FC = () => {
  const { reportConfig, setReportConfig, analysisData } = useStore();
  const [saved, setSaved] = useState(false);
  const [exporting, setExporting] = useState(false);

  const handleSectionToggle = (section: keyof typeof reportConfig.selectedSections) => {
    setReportConfig({
      selectedSections: {
        ...reportConfig.selectedSections,
        [section]: !reportConfig.selectedSections[section],
      },
    });
  };

  const handleSelectAll = () => {
    setReportConfig({
      selectedSections: {
        executiveSummary: true,
        dangerousFunctions: true,
        secrets: true,
        taintAnalysis: true,
        validationIssues: true,
        cryptoIssues: true,
        authIssues: true,
        frameworkIssues: true,
        qualityIssues: true,
        antipatterns: true,
        vulnerabilities: true,
      },
    });
  };

  const handleDeselectAll = () => {
    setReportConfig({
      selectedSections: {
        executiveSummary: false,
        dangerousFunctions: false,
        secrets: false,
        taintAnalysis: false,
        validationIssues: false,
        cryptoIssues: false,
        authIssues: false,
        frameworkIssues: false,
        qualityIssues: false,
        antipatterns: false,
        vulnerabilities: false,
      },
    });
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleExport = async () => {
    if (!analysisData) {
      alert('No analysis data available. Please load analysis data first.');
      return;
    }

    setExporting(true);
    try {
      if (reportConfig.exportFormat === 'pdf') {
        await exportToPDF(analysisData, reportConfig);
      } else if (reportConfig.exportFormat === 'json') {
        exportToJSON(analysisData, `security-analysis-${Date.now()}.json`);
      } else if (reportConfig.exportFormat === 'html') {
        // HTML export coming soon
        alert('HTML export will be available soon! For now, please use PDF or JSON.');
      }
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please check console for details.');
    } finally {
      setExporting(false);
    }
  };

  const sections = [
    { key: 'executiveSummary', label: 'Executive Summary Dashboard', icon: '📊' },
    { key: 'dangerousFunctions', label: 'Dangerous Functions', icon: '⚠️' },
    { key: 'secrets', label: 'Secrets & Credentials', icon: '🔑' },
    { key: 'taintAnalysis', label: 'Taint Analysis', icon: '🌊' },
    { key: 'validationIssues', label: 'Validation Issues', icon: '🛡️' },
    { key: 'cryptoIssues', label: 'Cryptography', icon: '🔐' },
    { key: 'authIssues', label: 'Authentication', icon: '🔑' },
    { key: 'frameworkIssues', label: 'Framework Security', icon: '🏗️' },
    { key: 'qualityIssues', label: 'Code Quality', icon: '✨' },
    { key: 'antipatterns', label: 'Anti-Patterns', icon: '⚠️' },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔍' },
  ];

  return (
    <div>
      <PageHeader
        title="Report Configuration & Settings"
        subtitle="Customize your security analysis reports and export preferences"
        icon="⚙️"
      />

      <div style={{ display: 'grid', gap: theme.spacing.lg }}>
        {/* Report Sections */}
        <Card title="Select Report Sections" subtitle="Choose which sections to include in exported reports">
          <div style={{ display: 'flex', gap: theme.spacing.sm, marginBottom: theme.spacing.lg }}>
            <Button variant="secondary" size="sm" onClick={handleSelectAll}>
              ✓ Select All
            </Button>
            <Button variant="secondary" size="sm" onClick={handleDeselectAll}>
              ✗ Deselect All
            </Button>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
            gap: theme.spacing.md,
          }}>
            {sections.map((section) => {
              const key = section.key as keyof typeof reportConfig.selectedSections;
              const isSelected = reportConfig.selectedSections[key];

              return (
                <div
                  key={section.key}
                  onClick={() => handleSectionToggle(key)}
                  style={{
                    padding: theme.spacing.md,
                    background: isSelected ? theme.colors.background.cardHover : theme.colors.background.tertiary,
                    border: `2px solid ${isSelected ? theme.colors.accent.green : theme.colors.border.primary}`,
                    borderRadius: theme.borderRadius.md,
                    cursor: 'pointer',
                    transition: theme.transitions.fast,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.sm }}>
                    <span style={{ fontSize: '1.5rem' }}>{section.icon}</span>
                    <span style={{ color: theme.colors.text.primary, fontWeight: theme.typography.fontWeight.medium }}>
                      {section.label}
                    </span>
                  </div>
                  {isSelected && (
                    <Badge color={theme.colors.accent.green} size="sm">
                      ✓
                    </Badge>
                  )}
                </div>
              );
            })}
          </div>
        </Card>

        {/* Export Options */}
        <Card title="Export Options" subtitle="Configure export behavior">
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.md }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.sm, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={reportConfig.includeCharts}
                onChange={(e) => setReportConfig({ includeCharts: e.target.checked })}
                style={{ width: '20px', height: '20px' }}
              />
              <span style={{ color: theme.colors.text.primary }}>Include Charts & Visualizations</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.sm, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={reportConfig.includeCodeSnippets}
                onChange={(e) => setReportConfig({ includeCodeSnippets: e.target.checked })}
                style={{ width: '20px', height: '20px' }}
              />
              <span style={{ color: theme.colors.text.primary }}>Include Code Snippets</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.sm, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={reportConfig.includeRecommendations}
                onChange={(e) => setReportConfig({ includeRecommendations: e.target.checked })}
                style={{ width: '20px', height: '20px' }}
              />
              <span style={{ color: theme.colors.text.primary }}>Include Fix Recommendations</span>
            </label>

            <div style={{ marginTop: theme.spacing.md }}>
              <label style={{ display: 'block', marginBottom: theme.spacing.sm, color: theme.colors.text.primary }}>
                Export Format
              </label>
              <select
                value={reportConfig.exportFormat}
                onChange={(e) => setReportConfig({ exportFormat: e.target.value as any })}
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.background.tertiary,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.md,
                  color: theme.colors.text.primary,
                  fontSize: theme.typography.fontSize.base,
                  fontFamily: theme.typography.fontFamily.primary,
                }}
              >
                <option value="pdf">PDF Report</option>
                <option value="json">JSON Data</option>
                <option value="html">HTML Report</option>
              </select>
            </div>
          </div>
        </Card>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: theme.spacing.md }}>
          <Button variant="primary" onClick={handleSave} fullWidth>
            {saved ? '✓ Saved!' : '💾 Save Settings'}
          </Button>
          <Button 
            variant="ghost" 
            onClick={handleExport}
            disabled={exporting || !analysisData}
            fullWidth
          >
            {exporting ? '⏳ Generating...' : '📥 Export Report with Current Settings'}
          </Button>
        </div>
        
        {!analysisData && (
          <p style={{
            textAlign: 'center',
            color: theme.colors.text.tertiary,
            fontSize: theme.typography.fontSize.sm,
            marginTop: theme.spacing.sm,
          }}>
            ℹ️ Load analysis data first to enable export
          </p>
        )}
      </div>
    </div>
  );
};

export default Settings;


