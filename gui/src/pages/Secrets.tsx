import React, { useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState, FilePreviewModal } from '../components/common';
import { PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToCSV, getFileName, groupBy } from '../utils/helpers';

const Secrets: React.FC = () => {
  const { analysisData } = useStore();
  const [previewFile, setPreviewFile] = useState<{ file: string; line: number; title: string; description: string; severity: string } | null>(null);

  if (!analysisData || analysisData.secrets.length === 0) {
    return <EmptyState icon="🔑" title="No Secrets Found" description="Great! No hardcoded secrets detected" />;
  }

  const byType = groupBy(analysisData.secrets, 'type');
  const typeData = Object.entries(byType).map(([name, items]) => ({ name, value: items.length }));

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
        title="Hardcoded Secrets & Credentials"
        subtitle="Click 'View Code' to see hardcoded secrets in your source files"
        icon="🔑"
        stats={[
          { label: 'Total Secrets', value: analysisData.secrets.length, color: theme.colors.severity.critical },
          { label: 'Unique Types', value: Object.keys(byType).length },
          { label: 'Files Affected', value: new Set(analysisData.secrets.map(s => s.file)).size },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToCSV(analysisData.secrets, 'secrets.csv')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Secrets by Type" icon="📊">
          <PieChart data={typeData} height={300} />
        </Card>
      </div>

      <Card title="All Secrets Detected">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Type</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Context</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'center', color: theme.colors.text.secondary }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {analysisData.secrets.map((item, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}`, cursor: 'pointer', transition: theme.transitions.fast }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = theme.colors.background.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>
                  <td style={{ padding: theme.spacing.sm }}>
                    <Badge severity="CRITICAL" size="sm">{item.type}</Badge>
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm }}>
                    {getFileName(item.file)}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.tertiary }}>{item.line}</td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm, fontFamily: theme.typography.fontFamily.mono }}>
                    {item.context.substring(0, 60)}...
                  </td>
                  <td style={{ padding: theme.spacing.sm, textAlign: 'center' }}>
                    <button
                      onClick={() => setPreviewFile({
                        file: item.file,
                        line: item.line,
                        title: `${item.type} - Secret Detected`,
                        description: item.context,
                        severity: 'CRITICAL',
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

export default Secrets;


