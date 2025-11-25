import React, { useMemo } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { StatCard, Card, Badge, Button, EmptyState } from '../components/common';
import { PieChart, BarChart, LineChart } from '../components/charts';
import { theme } from '../styles/theme';
import { formatDate, formatNumber, getSeverityColor, calculateRiskScore } from '../utils/helpers';

const Dashboard: React.FC = () => {
  const { analysisData } = useStore();

  // Calculate dashboard metrics
  const metrics = useMemo(() => {
    if (!analysisData) return null;

    const summary = analysisData.summary;
    const riskScore = calculateRiskScore(
      summary.secrets_count,
      summary.dangerous_functions_count + summary.auth_issues_count,
      summary.validation_issues_count + summary.framework_issues_count,
      summary.quality_issues_count + summary.antipattern_count
    );

    // Severity breakdown data
    const severityData = [
      { 
        name: 'Critical', 
        value: summary.secrets_count, 
        color: theme.colors.severity.critical 
      },
      { 
        name: 'High', 
        value: summary.dangerous_functions_count + summary.auth_issues_count, 
        color: theme.colors.severity.high 
      },
      { 
        name: 'Medium', 
        value: summary.validation_issues_count + summary.crypto_issues_count, 
        color: theme.colors.severity.medium 
      },
      { 
        name: 'Low', 
        value: summary.quality_issues_count + summary.antipattern_count, 
        color: theme.colors.severity.low 
      },
    ].filter(item => item.value > 0);

    // Category breakdown
    const categoryData = [
      { name: 'Dangerous Functions', value: summary.dangerous_functions_count },
      { name: 'Secrets', value: summary.secrets_count },
      { name: 'Validation Issues', value: summary.validation_issues_count },
      { name: 'Crypto Issues', value: summary.crypto_issues_count },
      { name: 'Auth Issues', value: summary.auth_issues_count },
      { name: 'Framework Issues', value: summary.framework_issues_count },
      { name: 'Quality Issues', value: summary.quality_issues_count },
      { name: 'Anti-Patterns', value: summary.antipattern_count },
      { name: 'Vulnerabilities', value: summary.vulnerability_count },
    ].filter(item => item.value > 0).sort((a, b) => b.value - a.value);

    // Files with most issues
    const fileIssues: Record<string, number> = {};
    
    [...analysisData.dangerous_functions, ...analysisData.secrets, ...analysisData.taint_analysis].forEach(item => {
      const file = item.file;
      fileIssues[file] = (fileIssues[file] || 0) + 1;
    });

    const topFiles = Object.entries(fileIssues)
      .map(([name, value]) => ({ name: name.split(/[\\/]/).pop() || name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);

    // Historical trend (mock data - in real app would come from database)
    const trendData = [
      { name: 'Week 1', value: Math.floor(summary.total_issues * 0.6) },
      { name: 'Week 2', value: Math.floor(summary.total_issues * 0.75) },
      { name: 'Week 3', value: Math.floor(summary.total_issues * 0.85) },
      { name: 'Week 4', value: summary.total_issues },
    ];

    return {
      summary,
      riskScore,
      severityData,
      categoryData,
      topFiles,
      trendData,
    };
  }, [analysisData]);

  if (!analysisData || !metrics) {
    return (
      <EmptyState
        icon="📊"
        title="No Analysis Data Available"
        description="Upload or scan a project to see the security analysis dashboard"
        action={{
          label: 'Load Sample Data',
          onClick: () => window.location.reload(),
        }}
      />
    );
  }

  const { summary, riskScore, severityData, categoryData, topFiles, trendData } = metrics;

  return (
    <div>
      <PageHeader
        title="Executive Security Dashboard"
        subtitle="Comprehensive security analysis overview and risk assessment"
        icon="🛡️"
        actions={
          <>
            <Button variant="ghost" size="sm">
              🔄 Refresh
            </Button>
            <Button variant="primary" size="sm">
              📥 Export Dashboard
            </Button>
          </>
        }
      />

      {/* Key Metrics */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: theme.spacing.md,
        marginBottom: theme.spacing.xl,
      }}>
        <StatCard
          title="Risk Score"
          value={riskScore}
          subtitle={summary.risk_level}
          icon="🎯"
          color={getSeverityColor(summary.risk_level as any)}
          glow
        />
        <StatCard
          title="Total Files"
          value={formatNumber(summary.files_scanned)}
          subtitle="Analyzed"
          icon="📁"
          color={theme.colors.accent.cyan}
        />
        <StatCard
          title="Total Issues"
          value={formatNumber(summary.total_issues)}
          subtitle="Findings"
          icon="⚠️"
          color={theme.colors.severity.high}
        />
        <StatCard
          title="Critical Issues"
          value={formatNumber(summary.secrets_count)}
          subtitle="Secrets Found"
          icon="🔴"
          color={theme.colors.severity.critical}
          glow
        />
      </div>

      {/* Charts Section */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(2, 1fr)',
        gap: theme.spacing.lg,
        marginBottom: theme.spacing.xl,
      }}>
        {/* Severity Distribution */}
        <Card title="Severity Distribution" icon="📊">
          <PieChart
            data={severityData}
            height={300}
            donut
          />
        </Card>

        {/* Category Breakdown */}
        <Card title="Issues by Category" icon="📈">
          <BarChart
            data={categoryData.slice(0, 8)}
            height={300}
            color={theme.colors.accent.green}
          />
        </Card>
      </div>

      {/* More Charts */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(2, 1fr)',
        gap: theme.spacing.lg,
        marginBottom: theme.spacing.xl,
      }}>
        {/* Top Risky Files */}
        <Card title="Top 10 Riskiest Files" icon="📄">
          <BarChart
            data={topFiles}
            height={300}
            horizontal
            color={theme.colors.severity.high}
          />
        </Card>

        {/* Historical Trend */}
        <Card title="Issue Trend Over Time" icon="📉">
          <LineChart
            data={trendData}
            height={300}
            color={theme.colors.accent.cyan}
          />
        </Card>
      </div>

      {/* Summary Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: theme.spacing.md,
        marginBottom: theme.spacing.xl,
      }}>
        {/* Security Findings */}
        <Card title="Security Findings" icon="🔒">
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.sm }}>
            {[
              { label: 'Dangerous Functions', value: summary.dangerous_functions_count, color: theme.colors.severity.high },
              { label: 'Secrets Found', value: summary.secrets_count, color: theme.colors.severity.critical },
              { label: 'Taint Sources', value: summary.taint_sources_count, color: theme.colors.severity.medium },
              { label: 'Validation Issues', value: summary.validation_issues_count, color: theme.colors.severity.medium },
            ].map((item, index) => (
              <div key={index} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: theme.spacing.sm,
                background: theme.colors.background.tertiary,
                borderRadius: theme.borderRadius.sm,
              }}>
                <span style={{ color: theme.colors.text.secondary }}>{item.label}</span>
                <Badge color={item.color}>{formatNumber(item.value)}</Badge>
              </div>
            ))}
          </div>
        </Card>

        {/* Security Checks */}
        <Card title="Security Checks" icon="🛡️">
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.sm }}>
            {[
              { label: 'Cryptography', value: summary.crypto_issues_count, color: theme.colors.severity.high },
              { label: 'Authentication', value: summary.auth_issues_count, color: theme.colors.severity.high },
              { label: 'Framework Security', value: summary.framework_issues_count, color: theme.colors.severity.medium },
              { label: 'Vulnerabilities', value: summary.vulnerability_count, color: theme.colors.severity.critical },
            ].map((item, index) => (
              <div key={index} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: theme.spacing.sm,
                background: theme.colors.background.tertiary,
                borderRadius: theme.borderRadius.sm,
              }}>
                <span style={{ color: theme.colors.text.secondary }}>{item.label}</span>
                <Badge color={item.color}>{formatNumber(item.value)}</Badge>
              </div>
            ))}
          </div>
        </Card>

        {/* Code Quality */}
        <Card title="Code Quality" icon="✨">
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.sm }}>
            {[
              { label: 'Quality Issues', value: summary.quality_issues_count, color: theme.colors.severity.low },
              { label: 'Anti-Patterns', value: summary.antipattern_count, color: theme.colors.severity.medium },
              { label: 'Files Scanned', value: summary.files_scanned, color: theme.colors.accent.cyan },
              { label: 'Risk Level', value: summary.risk_level, color: getSeverityColor(summary.risk_level as any) },
            ].map((item, index) => (
              <div key={index} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: theme.spacing.sm,
                background: theme.colors.background.tertiary,
                borderRadius: theme.borderRadius.sm,
              }}>
                <span style={{ color: theme.colors.text.secondary }}>{item.label}</span>
                <Badge color={item.color}>{item.value}</Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Scan Metadata */}
      <Card title="Scan Information" icon="ℹ️">
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: theme.spacing.md,
        }}>
          <div>
            <p style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm }}>
              Project Path
            </p>
            <p style={{ color: theme.colors.text.primary, fontFamily: theme.typography.fontFamily.mono }}>
              {analysisData.metadata.project_path}
            </p>
          </div>
          <div>
            <p style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm }}>
              Scan Time
            </p>
            <p style={{ color: theme.colors.text.primary }}>
              {formatDate(analysisData.metadata.scan_time)}
            </p>
          </div>
          <div>
            <p style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm }}>
              Analyzer Version
            </p>
            <p style={{ color: theme.colors.accent.cyan }}>
              v{analysisData.metadata.analyzer_version}
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Dashboard;




