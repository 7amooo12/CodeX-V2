import React, { useMemo, useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, Button, EmptyState, FilePreviewModal } from '../components/common';
import { PieChart, BarChart } from '../components/charts';
import { theme } from '../styles/theme';
import { exportToJSON } from '../utils/helpers';

const Vulnerabilities: React.FC = () => {
  const { analysisData } = useStore();
  const [previewFile, setPreviewFile] = useState<{ file: string; line: number; title: string; description: string; severity: string } | null>(null);

  const vulnData = useMemo(() => {
    if (!analysisData?.vulnerability_scan) return null;

    const scan = analysisData.vulnerability_scan;
    const severity = scan.severity_breakdown || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

    const severityData = [
      { name: 'Critical', value: severity.CRITICAL, color: theme.colors.severity.critical },
      { name: 'High', value: severity.HIGH, color: theme.colors.severity.high },
      { name: 'Medium', value: severity.MEDIUM, color: theme.colors.severity.medium },
      { name: 'Low', value: severity.LOW, color: theme.colors.severity.low },
    ].filter(item => item.value > 0);

    const packageData = (scan.packages || [])
      .map(pkg => ({
        name: pkg.name,
        value: pkg.vulnerabilities?.length || 0,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);

    return { scan, severityData, packageData };
  }, [analysisData]);

  if (!analysisData || !vulnData || vulnData.scan.total_vulnerabilities === 0) {
    return <EmptyState icon="🔍" title="No Vulnerabilities" description="No dependency vulnerabilities found" />;
  }

  const { scan, severityData, packageData } = vulnData;

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
        title="Vulnerability Management Report"
        subtitle="Dependency vulnerabilities (CVEs) - These are in third-party packages, not your source code"
        icon="🔍"
        stats={[
          { label: 'Dependencies', value: scan.total_dependencies },
          { label: 'Vulnerable', value: scan.vulnerable_packages, color: theme.colors.severity.high },
          { label: 'CVEs', value: scan.total_vulnerabilities, color: theme.colors.severity.critical },
        ]}
        actions={
          <Button variant="ghost" size="sm" onClick={() => exportToJSON(scan, 'vulnerabilities.json')}>
            📥 Export
          </Button>
        }
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing.lg, marginBottom: theme.spacing.xl }}>
        <Card title="Severity Distribution"><PieChart data={severityData} height={300} donut /></Card>
        <Card title="Top Vulnerable Packages"><BarChart data={packageData} height={300} horizontal color={theme.colors.severity.critical} /></Card>
      </div>

      <Card title="Vulnerable Dependencies">
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.md }}>
          {(scan.packages || []).map((pkg, index) => (
            <div
              key={index}
              style={{
                padding: theme.spacing.lg,
                background: theme.colors.background.tertiary,
                border: `1px solid ${theme.colors.border.primary}`,
                borderRadius: theme.borderRadius.lg,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: theme.spacing.md }}>
                <div>
                  <h4 style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                    {pkg.name}@{pkg.version}
                  </h4>
                  <p style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm }}>
                    {pkg.ecosystem}
                  </p>
                </div>
                <Badge severity="HIGH" glow>
                  {pkg.vulnerabilities?.length || 0} CVEs
                </Badge>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.md }}>
                {(pkg.vulnerabilities || []).map((vuln, vIndex) => (
                  <div
                    key={vIndex}
                    style={{
                      padding: theme.spacing.lg,
                      background: theme.colors.background.card,
                      border: `2px solid ${theme.colors.border.tertiary}`,
                      borderRadius: theme.borderRadius.lg,
                      fontSize: theme.typography.fontSize.sm,
                    }}
                  >
                    {/* CVE IDs - Prominently displayed */}
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: theme.spacing.sm, 
                      marginBottom: theme.spacing.md,
                      flexWrap: 'wrap'
                    }}>
                      {vuln.cve_ids && vuln.cve_ids.length > 0 ? (
                        vuln.cve_ids.map((cveId: string, cveIndex: number) => (
                          <div 
                            key={cveIndex}
                            style={{ 
                              fontFamily: theme.typography.fontFamily.mono, 
                              color: theme.colors.accent.cyan,
                              fontSize: theme.typography.fontSize.xl,
                              fontWeight: theme.typography.fontWeight.bold,
                              background: `linear-gradient(135deg, ${theme.colors.accent.cyan}30, ${theme.colors.accent.green}30)`,
                              padding: `${theme.spacing.sm} ${theme.spacing.md}`,
                              borderRadius: theme.borderRadius.md,
                              border: `2px solid ${theme.colors.accent.cyan}`,
                              boxShadow: `0 0 25px ${theme.colors.accent.cyan}60, inset 0 0 10px ${theme.colors.accent.cyan}20`,
                              textShadow: `0 0 15px ${theme.colors.accent.cyan}`,
                              letterSpacing: '0.05em',
                            }}
                          >
                            {cveId}
                          </div>
                        ))
                      ) : (
                        <div style={{ 
                          fontFamily: theme.typography.fontFamily.mono, 
                          color: theme.colors.accent.cyan,
                          fontSize: theme.typography.fontSize.xl,
                          fontWeight: theme.typography.fontWeight.bold,
                          background: `linear-gradient(135deg, ${theme.colors.accent.cyan}30, ${theme.colors.accent.green}30)`,
                          padding: `${theme.spacing.sm} ${theme.spacing.md}`,
                          borderRadius: theme.borderRadius.md,
                          border: `2px solid ${theme.colors.accent.cyan}`,
                          boxShadow: `0 0 25px ${theme.colors.accent.cyan}60, inset 0 0 10px ${theme.colors.accent.cyan}20`,
                          textShadow: `0 0 15px ${theme.colors.accent.cyan}`,
                          letterSpacing: '0.05em',
                        }}>
                          {vuln.id}
                        </div>
                      )}
                      
                      <Badge severity={vuln.severity} glow>
                        {vuln.severity}
                      </Badge>
                      
                      {vuln.cvss_score && (
                        <div style={{
                          fontFamily: theme.typography.fontFamily.mono,
                          fontSize: theme.typography.fontSize.sm,
                          color: theme.colors.severity.critical,
                          padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                          background: `${theme.colors.severity.critical}20`,
                          border: `1px solid ${theme.colors.severity.critical}`,
                          borderRadius: theme.borderRadius.sm,
                          fontWeight: theme.typography.fontWeight.bold,
                        }}>
                          CVSS: {vuln.cvss_score}
                        </div>
                      )}
                    </div>

                    {/* Summary */}
                    <div style={{ 
                      color: theme.colors.text.primary, 
                      marginBottom: theme.spacing.md,
                      lineHeight: '1.6',
                      fontSize: theme.typography.fontSize.base,
                    }}>
                      {vuln.summary || 'No description available'}
                    </div>

                    {/* References */}
                    {vuln.references && vuln.references.length > 0 && (
                      <div style={{
                        marginBottom: theme.spacing.md,
                        padding: theme.spacing.sm,
                        background: `${theme.colors.background.tertiary}80`,
                        border: `1px solid ${theme.colors.border.tertiary}`,
                        borderRadius: theme.borderRadius.sm,
                      }}>
                        <div style={{
                          color: theme.colors.accent.cyan,
                          fontWeight: theme.typography.fontWeight.bold,
                          fontSize: theme.typography.fontSize.sm,
                          marginBottom: theme.spacing.xs,
                        }}>
                          📎 References:
                        </div>
                        <div style={{
                          display: 'flex',
                          flexDirection: 'column',
                          gap: theme.spacing.xs,
                        }}>
                          {vuln.references.slice(0, 5).map((ref: string, refIndex: number) => (
                            <a
                              key={refIndex}
                              href={ref}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                color: theme.colors.accent.cyan,
                                fontSize: theme.typography.fontSize.xs,
                                textDecoration: 'none',
                                fontFamily: theme.typography.fontFamily.mono,
                                wordBreak: 'break-all',
                                transition: 'color 0.2s',
                              }}
                              onMouseEnter={(e) => e.currentTarget.style.color = theme.colors.accent.green}
                              onMouseLeave={(e) => e.currentTarget.style.color = theme.colors.accent.cyan}
                            >
                              → {ref}
                            </a>
                          ))}
                          {vuln.references.length > 5 && (
                            <div style={{
                              color: theme.colors.text.tertiary,
                              fontSize: theme.typography.fontSize.xs,
                              fontStyle: 'italic',
                            }}>
                              + {vuln.references.length - 5} more references
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Fixed Versions */}
                    {vuln.fixed_versions && vuln.fixed_versions.length > 0 && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: theme.spacing.sm,
                        padding: theme.spacing.sm,
                        background: `${theme.colors.accent.green}10`,
                        border: `1px solid ${theme.colors.accent.green}40`,
                        borderRadius: theme.borderRadius.sm,
                        marginTop: theme.spacing.sm,
                      }}>
                        <span style={{ 
                          color: theme.colors.accent.green,
                          fontWeight: theme.typography.fontWeight.bold,
                          fontSize: theme.typography.fontSize.sm,
                        }}>
                          ✓ Fixed in:
                        </span>
                        <span style={{
                          fontSize: theme.typography.fontSize.sm,
                          color: theme.colors.accent.green,
                          fontFamily: theme.typography.fontFamily.mono,
                        }}>
                          {vuln.fixed_versions.join(', ')}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default Vulnerabilities;

