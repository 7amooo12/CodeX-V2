import React from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, EmptyState } from '../components/common';
import { PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { getFileName } from '../utils/helpers';

const CodeQuality: React.FC = () => {
  const { analysisData } = useStore();

  if (!analysisData || !analysisData.quality_issues || Object.keys(analysisData.quality_issues).length === 0) {
    return <EmptyState icon="✨" title="No Quality Issues" description="Code quality looks great!" />;
  }

  const allIssues = Object.entries(analysisData.quality_issues).flatMap(([type, items]) =>
    items.map(item => ({ ...item, type }))
  );

  const categoryData = Object.entries(analysisData.quality_issues).map(([name, items]) => ({
    name,
    value: items.length,
  }));

  return (
    <div>
      <PageHeader
        title="Code Quality & Maintainability"
        subtitle="Code smells, maintainability issues, and best practice violations"
        icon="✨"
        stats={[
          { label: 'Total Issues', value: allIssues.length, color: theme.colors.severity.low },
        ]}
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Issues by Category"><PieChart data={categoryData} height={300} /></Card>
      </div>

      <Card title="All Quality Issues">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Category</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Message</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Line</th>
              </tr>
            </thead>
            <tbody>
              {allIssues.map((item: any, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}` }}>
                  <td style={{ padding: theme.spacing.sm }}>
                    <Badge variant="subtle">{item.type || 'Quality Issue'}</Badge>
                  </td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>
                    {item.message || item.context || 'Quality issue detected'}
                  </td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>
                    {getFileName(item.file || '')}
                  </td>
                  <td style={{ padding: theme.spacing.sm }}>{item.line || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default CodeQuality;

