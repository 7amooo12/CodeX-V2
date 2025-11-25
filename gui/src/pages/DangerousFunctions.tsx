import React, { useMemo, useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState, FunctionDetailModal, FilePreviewModal } from '../components/common';
import { BarChart, PieChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToCSV, getFileName, groupBy } from '../utils/helpers';
import { DangerousFunction } from '../types';

const DangerousFunctions: React.FC = () => {
  const { analysisData } = useStore();
  const [selectedFunction, setSelectedFunction] = useState<DangerousFunction | null>(null);
  const [previewFile, setPreviewFile] = useState<{ file: string; line: number; title: string; description: string; severity: string } | null>(null);

  const stats = useMemo(() => {
    if (!analysisData) return null;

    const functions = analysisData.dangerous_functions;
    const byFunction = groupBy(functions, 'function');
    const byCategory = groupBy(functions, 'category');

    const topFunctions = Object.entries(byFunction)
      .map(([name, items]) => ({ name, value: items.length }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);

    const categoryData = Object.entries(byCategory)
      .map(([name, items]) => ({ name, value: items.length }));

    return { functions, topFunctions, categoryData };
  }, [analysisData]);

  if (!analysisData || !stats) {
    return <EmptyState icon="⚠️" title="No Data" description="No dangerous functions detected" />;
  }

  return (
    <div>
      {selectedFunction && (
        <FunctionDetailModal
          finding={selectedFunction}
          onClose={() => setSelectedFunction(null)}
        />
      )}

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
        title="Dangerous Functions Analysis"
        subtitle="Click 'View Code' to see the actual vulnerability in the source file with syntax highlighting"
        icon="⚠️"
        stats={[
          { label: 'Total Occurrences', value: stats.functions.length, color: theme.colors.severity.high },
          { label: 'Unique Functions', value: stats.topFunctions.length },
          { label: 'Files Affected', value: new Set(stats.functions.map(f => f.file)).size },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToCSV(stats.functions, 'dangerous-functions.csv')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing.lg, marginBottom: theme.spacing.xl }}>
        <Card title="Top Dangerous Functions" icon="📊">
          <BarChart data={stats.topFunctions} height={300} color={theme.colors.severity.high} />
        </Card>
        <Card title="By Category" icon="📈">
          <PieChart data={stats.categoryData} height={300} />
        </Card>
      </div>

      <Card title="All Findings" subtitle="Click any row to view detailed analysis">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.colors.border.primary}` }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Function</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Category</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary }}>Context</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'center', color: theme.colors.text.secondary }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {stats.functions.map((item, index) => (
                <tr
                  key={index}
                  onClick={() => setSelectedFunction(item)}
                  style={{
                    borderBottom: `1px solid ${theme.colors.border.tertiary}`,
                    cursor: 'pointer',
                    transition: theme.transitions.fast,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = theme.colors.background.cardHover;
                    e.currentTarget.style.borderLeftWidth = '3px';
                    e.currentTarget.style.borderLeftColor = theme.colors.accent.cyan;
                    e.currentTarget.style.borderLeftStyle = 'solid';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.borderLeft = 'none';
                  }}
                >
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono, fontWeight: theme.typography.fontWeight.semibold }}>
                    {item.function}()
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.primary }}>
                    <Badge variant="subtle">{item.category}</Badge>
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm }}>
                    {getFileName(item.file)}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.tertiary }}>{item.line}</td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm, fontFamily: theme.typography.fontFamily.mono }}>
                    {item.context.length > 80 ? item.context.substring(0, 80) + '...' : item.context}
                  </td>
                  <td style={{ padding: theme.spacing.sm, textAlign: 'center' }}>
                    <div style={{ display: 'flex', gap: theme.spacing.xs, justifyContent: 'center' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setPreviewFile({
                            file: item.file,
                            line: item.line,
                            title: `${item.function}() - ${item.category}`,
                            description: item.context,
                            severity: item.severity || 'HIGH',
                          });
                        }}
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
                      <span
                        style={{
                          color: theme.colors.accent.green,
                          fontSize: theme.typography.fontSize.sm,
                          fontWeight: theme.typography.fontWeight.semibold,
                          cursor: 'pointer',
                        }}
                      >
                        📋 Details →
                      </span>
                    </div>
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

export default DangerousFunctions;


