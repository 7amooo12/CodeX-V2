import React from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState } from '../components/common';
import { PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToCSV, getFileName, groupBy } from '../utils/helpers';

const Cryptography: React.FC = () => {
  const { analysisData } = useStore();

  if (!analysisData || analysisData.crypto_issues.length === 0) {
    return <EmptyState icon="🔐" title="No Crypto Issues" description="No cryptography misuse detected" />;
  }

  const byType = groupBy(analysisData.crypto_issues, 'type');
  const typeData = Object.entries(byType).map(([name, items]) => ({ name, value: items.length }));

  return (
    <div>
      <PageHeader
        title="Cryptography Misuse Analysis"
        subtitle="Weak algorithms, insecure configurations, and crypto vulnerabilities"
        icon="🔐"
        stats={[
          { label: 'Total Issues', value: analysisData.crypto_issues.length, color: theme.colors.severity.high },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToCSV(analysisData.crypto_issues, 'crypto-issues.csv')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ marginBottom: theme.spacing.xl }}>
        <Card title="Issues by Type"><PieChart data={typeData} height={300} /></Card>
      </div>

      <Card title="All Cryptography Issues">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Severity</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Type</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Message</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left' }}>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {analysisData.crypto_issues.map((item, index) => (
                <tr key={index} style={{ borderBottom: `1px solid ${theme.colors.border.tertiary}` }}>
                  <td style={{ padding: theme.spacing.sm }}><Badge severity={item.severity as any} size="sm">{item.severity}</Badge></td>
                  <td style={{ padding: theme.spacing.sm, fontFamily: theme.typography.fontFamily.mono }}>{item.type}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>{item.message}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm }}>{getFileName(item.file || item.filepath || '')}</td>
                  <td style={{ padding: theme.spacing.sm, fontSize: theme.typography.fontSize.sm, color: theme.colors.accent.green }}>{item.recommendation || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default Cryptography;




