import React, { useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, EmptyState, FilePreviewModal } from '../components/common';
import { PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { getFileName } from '../utils/helpers';

const AntiPatterns: React.FC = () => {
  const { analysisData } = useStore();
  const [previewFile, setPreviewFile] = useState<{ file: string; line: number; title: string; description: string; severity: string } | null>(null);

  if (!analysisData || !analysisData.antipatterns || Object.keys(analysisData.antipatterns).length === 0) {
    return <EmptyState icon="⚠️" title="No Anti-Patterns" description="No anti-patterns detected" />;
  }

  const allPatterns = Object.entries(analysisData.antipatterns).flatMap(([type, items]) =>
    items.map(item => ({ ...item, type }))
  );

  const categoryData = Object.entries(analysisData.antipatterns).map(([name, items]) => ({
    name,
    value: items.length,
  }));

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
        title="Anti-Pattern & Security Issues Detection"
        subtitle="Click 'View Code' to see anti-patterns in your source code"
        icon="⚠️"
        stats={[
          { label: 'Total Anti-Patterns', value: allPatterns.length, color: theme.colors.severity.medium },
        ]}
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Anti-Patterns by Category"><PieChart data={categoryData} height={300} /></Card>
      </div>

      <Card title="All Anti-Patterns">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Pattern</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Context</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {allPatterns.map((item: any, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}`, cursor: 'pointer', transition: theme.transitions.fast }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = theme.colors.background.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>
                  <td style={{ padding: theme.spacing.sm }}>
                    <Badge variant="subtle" color={theme.colors.severity.medium}>
                      {item.pattern || item.type || 'Unknown'}
                    </Badge>
                  </td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>
                    {getFileName(item.file || '')}
                  </td>
                  <td style={{ padding: theme.spacing.sm }}>{item.line || 0}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm, fontFamily: theme.typography.fontFamily.mono }}>
                    {(item.context || item.message || '').substring(0, 60)}...
                  </td>
                  <td style={{ padding: theme.spacing.sm, textAlign: 'center' }}>
                    {item.file && item.line && (
                      <button
                        onClick={() => setPreviewFile({
                          file: item.file,
                          line: item.line,
                          title: `${item.pattern || item.type} - Anti-Pattern`,
                          description: item.context || item.message || 'Anti-pattern detected',
                          severity: 'MEDIUM',
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

export default AntiPatterns;

