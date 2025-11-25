import React from 'react';
import { theme } from '../../styles/theme';
import { DangerousFunction } from '../../types';
import { FunctionKnowledge, getFunctionKnowledge } from '../../data/dangerousFunctionsKnowledge';
import { Badge } from './Badge';
import { Button } from './Button';

interface FunctionDetailModalProps {
  finding: DangerousFunction;
  onClose: () => void;
}

export const FunctionDetailModal: React.FC<FunctionDetailModalProps> = ({ finding, onClose }) => {
  const knowledge = getFunctionKnowledge(finding.function);

  const getSeverityColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return theme.colors.severity.critical;
      case 'HIGH':
        return theme.colors.severity.high;
      case 'MEDIUM':
        return theme.colors.severity.medium;
      default:
        return theme.colors.severity.low;
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(2, 11, 20, 0.95)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: theme.spacing.xl,
        backdropFilter: 'blur(8px)',
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.colors.background.card,
          border: `2px solid ${getSeverityColor(knowledge.riskLevel)}`,
          borderRadius: theme.borderRadius.lg,
          maxWidth: '1000px',
          maxHeight: '90vh',
          width: '100%',
          overflow: 'auto',
          boxShadow: `0 20px 60px ${getSeverityColor(knowledge.riskLevel)}40`,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: theme.spacing.xl,
            borderBottom: `1px solid ${theme.colors.border.primary}`,
            position: 'sticky',
            top: 0,
            background: theme.colors.background.card,
            zIndex: 1,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.md, marginBottom: theme.spacing.sm }}>
                <h2
                  style={{
                    fontSize: theme.typography.fontSize['3xl'],
                    fontWeight: theme.typography.fontWeight.bold,
                    color: theme.colors.accent.cyan,
                    fontFamily: theme.typography.fontFamily.mono,
                    margin: 0,
                  }}
                >
                  {knowledge.name}()
                </h2>
                <Badge
                  variant="danger"
                  style={{
                    background: `${getSeverityColor(knowledge.riskLevel)}20`,
                    color: getSeverityColor(knowledge.riskLevel),
                    border: `1px solid ${getSeverityColor(knowledge.riskLevel)}`,
                  }}
                >
                  {knowledge.riskLevel} RISK
                </Badge>
                <Badge variant="subtle">{knowledge.category}</Badge>
              </div>
              <p
                style={{
                  fontSize: theme.typography.fontSize.lg,
                  color: theme.colors.text.secondary,
                  margin: 0,
                }}
              >
                {knowledge.description}
              </p>
            </div>
            <button
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                color: theme.colors.text.tertiary,
                fontSize: '2rem',
                cursor: 'pointer',
                padding: theme.spacing.xs,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>
        </div>

        <div style={{ padding: theme.spacing.xl }}>
          {/* Location in Code */}
          <Section title="📍 Found in Your Code" icon="📍">
            <div
              style={{
                background: theme.colors.background.tertiary,
                padding: theme.spacing.md,
                borderRadius: theme.borderRadius.md,
                border: `1px solid ${theme.colors.border.secondary}`,
              }}
            >
              <div style={{ marginBottom: theme.spacing.sm }}>
                <strong style={{ color: theme.colors.text.primary }}>File:</strong>{' '}
                <code
                  style={{
                    color: theme.colors.accent.cyan,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                  }}
                >
                  {finding.file}
                </code>
              </div>
              <div style={{ marginBottom: theme.spacing.md }}>
                <strong style={{ color: theme.colors.text.primary }}>Line:</strong>{' '}
                <code style={{ color: theme.colors.accent.green }}>{finding.line}</code>
              </div>
              <div>
                <strong style={{ color: theme.colors.text.primary, display: 'block', marginBottom: theme.spacing.xs }}>
                  Code Snippet:
                </strong>
                <pre
                  style={{
                    background: theme.colors.background.secondary,
                    padding: theme.spacing.md,
                    borderRadius: theme.borderRadius.sm,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.primary,
                    overflow: 'auto',
                    margin: 0,
                    border: `1px solid ${getSeverityColor(knowledge.riskLevel)}40`,
                  }}
                >
                  {finding.context}
                </pre>
              </div>
            </div>
          </Section>

          {/* Security Risks */}
          <Section title="⚠️ Security Risks" icon="⚠️">
            <ul style={{ margin: 0, paddingLeft: theme.spacing.lg }}>
              {knowledge.risks.map((risk, index) => (
                <li
                  key={index}
                  style={{
                    color: theme.colors.text.secondary,
                    marginBottom: theme.spacing.sm,
                    lineHeight: 1.6,
                  }}
                >
                  {risk}
                </li>
              ))}
            </ul>
          </Section>

          {/* Recommendations */}
          <Section title="✅ Recommendations" icon="✅">
            <ul style={{ margin: 0, paddingLeft: theme.spacing.lg }}>
              {knowledge.recommendations.map((rec, index) => (
                <li
                  key={index}
                  style={{
                    color: theme.colors.text.secondary,
                    marginBottom: theme.spacing.sm,
                    lineHeight: 1.6,
                  }}
                >
                  {rec}
                </li>
              ))}
            </ul>
          </Section>

          {/* Safe Alternatives */}
          <Section title="🛡️ Safe Alternatives" icon="🛡️">
            <div
              style={{
                background: `${theme.colors.accent.green}10`,
                padding: theme.spacing.md,
                borderRadius: theme.borderRadius.md,
                border: `1px solid ${theme.colors.accent.green}40`,
              }}
            >
              <ul style={{ margin: 0, paddingLeft: theme.spacing.lg }}>
                {knowledge.safeAlternatives.map((alt, index) => (
                  <li
                    key={index}
                    style={{
                      color: theme.colors.accent.green,
                      marginBottom: theme.spacing.sm,
                      lineHeight: 1.6,
                    }}
                  >
                    {alt}
                  </li>
                ))}
              </ul>
            </div>
          </Section>

          {/* Code Examples */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing.lg }}>
            {/* Dangerous Example */}
            <div>
              <Section title="❌ Dangerous Usage" icon="❌">
                <pre
                  style={{
                    background: `${theme.colors.severity.critical}10`,
                    padding: theme.spacing.md,
                    borderRadius: theme.borderRadius.md,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.primary,
                    overflow: 'auto',
                    margin: 0,
                    border: `1px solid ${theme.colors.severity.critical}40`,
                    lineHeight: 1.5,
                  }}
                >
                  {knowledge.dangerousExample.code}
                </pre>
                <p
                  style={{
                    marginTop: theme.spacing.md,
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.secondary,
                    lineHeight: 1.6,
                  }}
                >
                  <strong style={{ color: theme.colors.severity.critical }}>Why it's dangerous:</strong>{' '}
                  {knowledge.dangerousExample.explanation}
                </p>
              </Section>
            </div>

            {/* Safe Example */}
            <div>
              <Section title="✅ Safe Usage" icon="✅">
                <pre
                  style={{
                    background: `${theme.colors.accent.green}10`,
                    padding: theme.spacing.md,
                    borderRadius: theme.borderRadius.md,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.primary,
                    overflow: 'auto',
                    margin: 0,
                    border: `1px solid ${theme.colors.accent.green}40`,
                    lineHeight: 1.5,
                  }}
                >
                  {knowledge.safeExample.code}
                </pre>
                <p
                  style={{
                    marginTop: theme.spacing.md,
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.secondary,
                    lineHeight: 1.6,
                  }}
                >
                  <strong style={{ color: theme.colors.accent.green }}>Why it's safe:</strong>{' '}
                  {knowledge.safeExample.explanation}
                </p>
              </Section>
            </div>
          </div>

          {/* References */}
          {(knowledge.cwe || knowledge.owasp) && (
            <Section title="📚 Security References" icon="📚">
              <div style={{ display: 'flex', gap: theme.spacing.lg, flexWrap: 'wrap' }}>
                {knowledge.cwe && (
                  <div>
                    <strong style={{ color: theme.colors.text.primary, display: 'block', marginBottom: theme.spacing.xs }}>
                      CWE:
                    </strong>
                    <div style={{ display: 'flex', gap: theme.spacing.xs, flexWrap: 'wrap' }}>
                      {knowledge.cwe.map((cwe, index) => (
                        <a
                          key={index}
                          href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            background: `${theme.colors.accent.cyan}20`,
                            color: theme.colors.accent.cyan,
                            padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                            borderRadius: theme.borderRadius.sm,
                            fontSize: theme.typography.fontSize.sm,
                            textDecoration: 'none',
                            border: `1px solid ${theme.colors.accent.cyan}40`,
                          }}
                        >
                          {cwe}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                {knowledge.owasp && (
                  <div>
                    <strong style={{ color: theme.colors.text.primary, display: 'block', marginBottom: theme.spacing.xs }}>
                      OWASP Top 10:
                    </strong>
                    <div style={{ display: 'flex', gap: theme.spacing.xs, flexWrap: 'wrap' }}>
                      {knowledge.owasp.map((owasp, index) => (
                        <Badge
                          key={index}
                          variant="subtle"
                          style={{
                            background: `${theme.colors.accent.green}20`,
                            color: theme.colors.accent.green,
                          }}
                        >
                          {owasp}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Footer Actions */}
          <div
            style={{
              marginTop: theme.spacing.xl,
              paddingTop: theme.spacing.lg,
              borderTop: `1px solid ${theme.colors.border.primary}`,
              display: 'flex',
              justifyContent: 'flex-end',
            }}
          >
            <Button variant="primary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Helper Section Component
const Section: React.FC<{ title: string; icon: string; children: React.ReactNode }> = ({ title, icon, children }) => (
  <div style={{ marginBottom: theme.spacing.xl }}>
    <h3
      style={{
        fontSize: theme.typography.fontSize.xl,
        fontWeight: theme.typography.fontWeight.semibold,
        color: theme.colors.text.primary,
        marginBottom: theme.spacing.md,
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing.sm,
      }}
    >
      <span>{icon}</span>
      {title}
    </h3>
    {children}
  </div>
);



