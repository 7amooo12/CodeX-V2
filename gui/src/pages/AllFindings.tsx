import React, { useMemo, useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState } from '../components/common';
import { theme } from '../styles/theme';
import { UnifiedFinding } from '../types';
import { formatNumber, exportToCSV, exportToJSON, getFileName } from '../utils/helpers';

const AllFindings: React.FC = () => {
  const { analysisData } = useStore();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState<'severity' | 'file' | 'category'>('severity');

  // Consolidate all findings
  const allFindings = useMemo((): UnifiedFinding[] => {
    if (!analysisData) return [];

    const findings: UnifiedFinding[] = [];

    // Dangerous Functions
    analysisData.dangerous_functions.forEach((item, index) => {
      findings.push({
        id: `df-${index}`,
        category: 'Dangerous Function',
        vulnerability: item.function,
        file: item.file,
        line: item.line,
        severity: item.severity || 'HIGH',
        description: item.context,
        context: item.context,
      });
    });

    // Secrets
    analysisData.secrets.forEach((item, index) => {
      findings.push({
        id: `secret-${index}`,
        category: 'Secret/Credential',
        vulnerability: item.type,
        file: item.file,
        line: item.line,
        severity: 'CRITICAL',
        description: item.context,
        context: item.context,
      });
    });

    // Validation Issues
    analysisData.validation_issues.forEach((item, index) => {
      findings.push({
        id: `val-${index}`,
        category: 'Validation Issue',
        vulnerability: item.type,
        file: item.file || item.filepath || '',
        line: item.line,
        severity: item.severity,
        description: item.message,
        recommendation: item.recommendation,
      });
    });

    // Crypto Issues
    analysisData.crypto_issues.forEach((item, index) => {
      findings.push({
        id: `crypto-${index}`,
        category: 'Cryptography',
        vulnerability: item.type,
        file: item.file || item.filepath || '',
        line: item.line,
        severity: item.severity,
        description: item.message,
        recommendation: item.recommendation,
      });
    });

    // Auth Issues
    analysisData.auth_issues.forEach((item, index) => {
      findings.push({
        id: `auth-${index}`,
        category: 'Authentication',
        vulnerability: item.type,
        file: item.file || item.filepath || '',
        line: item.line,
        severity: item.severity,
        description: item.message,
      });
    });

    // Framework Issues
    analysisData.framework_issues.forEach((item, index) => {
      findings.push({
        id: `fw-${index}`,
        category: 'Framework Security',
        vulnerability: item.type,
        file: item.file || item.filepath || '',
        line: item.line,
        severity: item.severity,
        description: item.message,
        recommendation: item.recommendation,
      });
    });

    return findings;
  }, [analysisData]);

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let filtered = [...allFindings];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(f =>
        f.vulnerability.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.file.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Severity filter
    if (severityFilter.length > 0) {
      filtered = filtered.filter(f => severityFilter.includes(f.severity));
    }

    // Category filter
    if (categoryFilter.length > 0) {
      filtered = filtered.filter(f => categoryFilter.includes(f.category));
    }

    // Sort
    filtered.sort((a, b) => {
      if (sortBy === 'severity') {
        const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
      } else if (sortBy === 'file') {
        return a.file.localeCompare(b.file);
      } else if (sortBy === 'category') {
        return a.category.localeCompare(b.category);
      }
      return 0;
    });

    return filtered;
  }, [allFindings, searchTerm, severityFilter, categoryFilter, sortBy]);

  const handleExport = (format: 'csv' | 'json') => {
    const data = filteredFindings.map(f => ({
      Category: f.category,
      Vulnerability: f.vulnerability,
      File: f.file,
      Line: f.line,
      Severity: f.severity,
      Description: f.description,
      Recommendation: f.recommendation || 'N/A',
    }));

    if (format === 'csv') {
      exportToCSV(data, 'security-findings.csv');
    } else {
      exportToJSON(data, 'security-findings.json');
    }
  };

  if (!analysisData) {
    return (
      <EmptyState
        icon="📋"
        title="No Findings Available"
        description="Run a security analysis to see findings"
      />
    );
  }

  return (
    <div>
      <PageHeader
        title="All Security Findings"
        subtitle="Consolidated, deduplicated findings from all security modules"
        icon="📋"
        stats={[
          { label: 'Total Findings', value: allFindings.length },
          { label: 'Filtered', value: filteredFindings.length },
          { label: 'Critical', value: allFindings.filter(f => f.severity === 'CRITICAL').length, color: theme.colors.severity.critical },
        ]}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => handleExport('csv')}>
              📥 Export CSV
            </Button>
            <Button variant="ghost" size="sm" onClick={() => handleExport('json')}>
              📥 Export JSON
            </Button>
          </>
        }
      />

      {/* Filters */}
      <Card title="Filters" padding="md" style={{ marginBottom: theme.spacing.lg }}>
        <div style={{ display: 'flex', gap: theme.spacing.md, flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Search findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: 1,
              minWidth: '300px',
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
              fontSize: theme.typography.fontSize.base,
              fontFamily: theme.typography.fontFamily.primary,
            }}
          />

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            style={{
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
              fontSize: theme.typography.fontSize.base,
              fontFamily: theme.typography.fontFamily.primary,
            }}
          >
            <option value="severity">Sort by Severity</option>
            <option value="file">Sort by File</option>
            <option value="category">Sort by Category</option>
          </select>
        </div>
      </Card>

      {/* Findings Table */}
      <Card>
        <div style={{ overflowX: 'auto' }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
          }}>
            <thead>
              <tr style={{
                borderBottom: `2px solid ${theme.colors.border.primary}`,
              }}>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>Severity</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>Category</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>Vulnerability</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>File</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>Line</th>
                <th style={{ padding: theme.spacing.sm, textAlign: 'left', color: theme.colors.text.secondary, fontWeight: theme.typography.fontWeight.semibold }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  style={{
                    borderBottom: `1px solid ${theme.colors.border.tertiary}`,
                    transition: theme.transitions.fast,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = theme.colors.background.cardHover;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent';
                  }}
                >
                  <td style={{ padding: theme.spacing.sm }}>
                    <Badge severity={finding.severity as any} size="sm">
                      {finding.severity}
                    </Badge>
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.primary }}>
                    {finding.category}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                    {finding.vulnerability}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm }}>
                    {getFileName(finding.file)}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.tertiary }}>
                    {finding.line}
                  </td>
                  <td style={{ padding: theme.spacing.sm, color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm, maxWidth: '400px' }}>
                    {finding.description.substring(0, 100)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredFindings.length === 0 && (
            <div style={{ padding: theme.spacing.xl, textAlign: 'center', color: theme.colors.text.tertiary }}>
              No findings match your filters
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

export default AllFindings;




