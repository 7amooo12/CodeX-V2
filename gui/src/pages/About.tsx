import React from 'react';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge } from '../components/common';
import { theme } from '../styles/theme';

const About: React.FC = () => {
  return (
    <div>
      <PageHeader
        title="About CodeX Analysis Platform"
        subtitle="Security Analysis Tool"
        icon="ℹ️"
      />

      <div style={{ display: 'grid', gap: theme.spacing.lg }}>
        {/* Platform Overview */}
        <Card title="Platform Overview">
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.md }}>
            <p style={{ color: theme.colors.text.primary, fontSize: theme.typography.fontSize.base, lineHeight: '1.8' }}>
              <strong style={{ color: theme.colors.accent.cyan }}>CodeX</strong> is an enterprise-grade
              security code analysis platform designed to identify vulnerabilities, security risks,
              and code quality issues in modern applications.
            </p>
            <p style={{ color: theme.colors.text.secondary, lineHeight: '1.8' }}>
              Our comprehensive analysis engine scans your codebase across multiple dimensions including dangerous
              functions, hardcoded secrets, authentication flaws, cryptographic misuse, input validation issues,
              framework-specific vulnerabilities, and dependency vulnerabilities (CVEs).
            </p>
          </div>
        </Card>

        {/* Features */}
        <Card title="Key Features">
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: theme.spacing.md,
          }}>
            {[
              { icon: '⚠️', title: 'Dangerous Functions', desc: 'Detect potentially unsafe function calls' },
              { icon: '🔑', title: 'Secret Detection', desc: 'Find hardcoded credentials and API keys' },
              { icon: '🌊', title: 'Taint Analysis', desc: 'Track user input data flow' },
              { icon: '🛡️', title: 'Validation Checks', desc: 'Identify missing input validation' },
              { icon: '🔐', title: 'Crypto Analysis', desc: 'Detect weak cryptography' },
              { icon: '🔑', title: 'Auth Security', desc: 'Find authentication flaws' },
              { icon: '🏗️', title: 'Framework Checks', desc: 'Framework-specific vulnerabilities' },
              { icon: '✨', title: 'Code Quality', desc: 'Maintainability and best practices' },
              { icon: '🔍', title: 'CVE Scanning', desc: 'Dependency vulnerability detection' },
            ].map((feature, index) => (
              <div
                key={index}
                style={{
                  padding: theme.spacing.md,
                  background: theme.colors.background.tertiary,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.md,
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: theme.spacing.sm }}>{feature.icon}</div>
                <h4 style={{
                  color: theme.colors.accent.cyan,
                  fontSize: theme.typography.fontSize.base,
                  fontWeight: theme.typography.fontWeight.semibold,
                  marginBottom: theme.spacing.xs,
                }}>
                  {feature.title}
                </h4>
                <p style={{ color: theme.colors.text.secondary, fontSize: theme.typography.fontSize.sm }}>
                  {feature.desc}
                </p>
              </div>
            ))}
          </div>
        </Card>

        {/* Supported Languages */}
        <Card title="Supported Languages & Frameworks">
          <div style={{ display: 'flex', gap: theme.spacing.sm, flexWrap: 'wrap' }}>
            {['Python', 'JavaScript', 'TypeScript', 'Java', 'C#', '.NET', 'PHP', 'Ruby', 'Go', 'Django', 'Flask', 'Express', 'React', 'Vue', 'Angular', 'Spring'].map((lang) => (
              <Badge key={lang} color={theme.colors.accent.green} size="md">
                {lang}
              </Badge>
            ))}
          </div>
        </Card>

        {/* Technical Specs */}
        <Card title="Technical Specifications">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: theme.spacing.md }}>
            <div>
              <h4 style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm, marginBottom: theme.spacing.xs }}>
                Platform Version
              </h4>
              <p style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                v2.0.0
              </p>
            </div>
            <div>
              <h4 style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm, marginBottom: theme.spacing.xs }}>
                Analyzer Engine
              </h4>
              <p style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                Multi-Module Security Scanner
              </p>
            </div>
            <div>
              <h4 style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm, marginBottom: theme.spacing.xs }}>
                CVE Database
              </h4>
              <p style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                OSV, NVD, GitHub Security Advisory
              </p>
            </div>
            <div>
              <h4 style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm, marginBottom: theme.spacing.xs }}>
                Export Formats
              </h4>
              <p style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
                PDF, JSON, CSV, HTML
              </p>
            </div>
          </div>
        </Card>

        {/* License & Credits */}
        <Card title="License & Credits">
          <div style={{ color: theme.colors.text.secondary, lineHeight: '1.8' }}>
            <p style={{ marginBottom: theme.spacing.md }}>
              <strong style={{ color: theme.colors.text.primary }}>CodeX Analysis Platform</strong> - Enterprise Security Analysis Tool
            </p>
            <p style={{ marginBottom: theme.spacing.md }}>
              Built with React, TypeScript, ReportLab, and powered by comprehensive security analysis modules.
            </p>
            <p style={{ color: theme.colors.text.tertiary, fontSize: theme.typography.fontSize.sm }}>
              © 2025 CodeX Analysis Platform. All rights reserved.
            </p>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default About;

