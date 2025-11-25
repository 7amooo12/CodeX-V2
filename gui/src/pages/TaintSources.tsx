import React from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState } from '../components/common';
import { BarChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToCSV, getFileName, groupBy } from '../utils/helpers';

const TaintSources: React.FC = () => {
  const { analysisData } = useStore();

  if (!analysisData || analysisData.taint_analysis.length === 0) {
    return <EmptyState icon="🌊" title="No Taint Sources" description="No user input sources detected" />;
  }

  const byType = groupBy(analysisData.taint_analysis, 'type');
  const typeData = Object.entries(byType).map(([name, items]) => ({ name, value: items.length }));

  return (
    <div>
      <PageHeader
        title="User Input Sources (Taint Origins)"
        subtitle="Points where user-controllable data enters the application"
        icon="🌊"
        stats={[
          { label: 'Total Sources', value: analysisData.taint_analysis.length, color: theme.colors.severity.medium },
          { label: 'Types', value: Object.keys(byType).length },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToCSV(analysisData.taint_analysis, 'taint-sources.csv')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Sources by Type" icon="📊">
          <BarChart data={typeData} height={300} color={theme.colors.accent.cyan} />
        </Card>
      </div>

      <Card title="All Taint Sources">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Source</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Type</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Context</th>
              </tr>
            </thead>
            <tbody>
              {analysisData.taint_analysis.map((item, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}` }}>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                    {item.source}
                  </td>
                  <td style={{ padding: theme.spacing.sm }}><Badge variant="subtle">{item.type}</Badge></td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>{getFileName(item.file)}</td>
                  <td style={{ padding: theme.spacing.sm }}>{item.line}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm, fontFamily: theme.typography.fontFamily.mono }}>
                    {item.context.substring(0, 70)}...
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

export default TaintSources;




