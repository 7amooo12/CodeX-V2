import React, { useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState, FilePreviewModal } from '../components/common';
import { PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToCSV, getFileName, groupBy } from '../utils/helpers';

const FrameworkSecurity: React.FC = () => {
  const { analysisData } = useStore();
  const [previewFile, setPreviewFile] = useState<{ file: string; line: number; title: string; description: string; severity: string } | null>(null);

  if (!analysisData || analysisData.framework_issues.length === 0) {
    return <EmptyState icon="🏗️" title="No Framework Issues" description="No framework-specific issues detected" />;
  }

  const byFramework = groupBy(analysisData.framework_issues, 'framework');
  const frameworkData = Object.entries(byFramework).map(([name, items]) => ({ name, value: items.length }));

  return (
    <div>
      {previewFile && (
        <FilePreviewModal
          filePath={previewFile.file}
          line={previewFile.line}
          title={previewFile.title}
          description={previewFile.description}
          severity={previewFile.severity}
          onClose={() => setPreviewFile(null)}
        />
      )}

      <PageHeader
        title="Framework-Specific Security Findings"
        subtitle="Click 'View Code' to see framework security issues in your code"
        icon="🏗️"
        stats={[
          { label: 'Total Issues', value: analysisData.framework_issues.length, color: theme.colors.severity.medium },
          { label: 'Frameworks', value: Object.keys(byFramework).length },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToCSV(analysisData.framework_issues, 'framework-issues.csv')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Issues by Framework"><PieChart data={frameworkData} height={300} /></Card>
      </div>

      <Card title="All Framework Issues">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Severity</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Framework</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Type</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Message</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {analysisData.framework_issues.map((item, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}`, cursor: 'pointer', transition: theme.transitions.fast }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = theme.colors.background.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>
                  <td style={{ padding: theme.spacing.sm }}><Badge severity={item.severity as any} size="sm">{item.severity}</Badge></td>
                  <td style={{ padding: theme.spacing.sm }}><Badge variant="subtle" color={theme.colors.accent.purple}>{item.framework}</Badge></td>
                  <td style={{ padding: theme.spacing.sm, fontFamily: theme.typography.fontFamily.mono }}>{item.type}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>{item.message}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>{getFileName(item.file || item.filepath || '')}</td>
                  <td style={{ padding: theme.spacing.sm }}>{(item as any).line || '-'}</td>
                  <td style={{ padding: theme.spacing.sm, textAlign: 'center' }}>
                    {(item as any).line && (
                      <button
                        onClick={() => setPreviewFile({
                          file: item.file || item.filepath || '',
                          line: (item as any).line,
                          title: `${item.framework} - ${item.type}`,
                          description: item.message,
                          severity: item.severity || 'MEDIUM',
                        })}
                        style={{
                          padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                          background: `${theme.colors.accent.cyan}20`,
                          border: `1px solid ${theme.colors.accent.cyan}`,
                          borderRadius: theme.borderRadius.sm,
                          color: theme.colors.accent.cyan,
                          fontSize: theme.typography.fontSize.xs,
                          fontWeight: theme.typography.fontWeight.semibold,
                          cursor: 'pointer',
                          transition: theme.transitions.fast,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = theme.colors.accent.cyan;
                          e.currentTarget.style.color = theme.colors.background.primary;
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = `${theme.colors.accent.cyan}20`;
                          e.currentTarget.style.color = theme.colors.accent.cyan;
                        }}
                      >
                        🔍 View Code
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default FrameworkSecurity;



