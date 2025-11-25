import React, { useCallback } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, EmptyState } from '../components/common';
import { theme } from '../styles/theme';

// Note: This is a simplified version. In production, use react-flow-renderer for interactive graphs
const TaintFlows: React.FC = () => {
  const { analysisData } = useStore();

  if (!analysisData || !analysisData.taint_flows || analysisData.taint_flows.length === 0) {
    return (
      <EmptyState
        icon="🔄"
        title="No Taint Flow Data"
        description="Enable taint flow analysis to see data propagation graphs"
      />
    );
  }

  return (
    <div>
      <PageHeader
        title="Taint Flow Analysis"
        subtitle="Interactive visualization of data flow from sources to sinks"
        icon="🔄"
      />

      {/* Simplified visualization - In production, implement with react-flow-renderer */}
      <Card title="Data Flow Visualization" subtitle="Interactive graph showing how tainted data propagates">
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: theme.spacing.lg,
          padding: theme.spacing.xl,
        }}>
          {analysisData.taint_flows.map((flow, index) => (
            <div
              key={index}
              style={{
                padding: theme.spacing.lg,
                background: theme.colors.background.tertiary,
                border: `1px solid ${theme.colors.border.primary}`,
                borderRadius: theme.borderRadius.lg,
              }}
            >
              <div style={{ marginBottom: theme.spacing.md }}>
                <span style={{ color: theme.colors.text.tertiary }}>Flow #{index + 1}</span>
              </div>

              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: theme.spacing.md,
                flexWrap: 'wrap',
              }}>
                {/* Source */}
                <div
                  style={{
                    padding: theme.spacing.md,
                    background: theme.colors.accent.cyan,
                    color: theme.colors.background.primary,
                    borderRadius: theme.borderRadius.md,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                    fontWeight: theme.typography.fontWeight.semibold,
                    boxShadow: theme.shadows.glow.cyan,
                  }}
                >
                  🌊 {flow.source}
                </div>

                {/* Flow Path */}
                {flow.flow_path.map((step, stepIndex) => (
                  <React.Fragment key={stepIndex}>
                    <div style={{ color: theme.colors.accent.green, fontSize: '1.5rem' }}>→</div>
                    <div
                      style={{
                        padding: theme.spacing.md,
                        background: theme.colors.accent.blue,
                        color: theme.colors.text.primary,
                        borderRadius: theme.borderRadius.md,
                        fontFamily: theme.typography.fontFamily.mono,
                        fontSize: theme.typography.fontSize.sm,
                      }}
                    >
                      {step}
                    </div>
                  </React.Fragment>
                ))}

                <div style={{ color: theme.colors.severity.critical, fontSize: '1.5rem' }}>→</div>

                {/* Sink */}
                <div
                  style={{
                    padding: theme.spacing.md,
                    background: theme.colors.severity.critical,
                    color: theme.colors.text.primary,
                    borderRadius: theme.borderRadius.md,
                    fontFamily: theme.typography.fontFamily.mono,
                    fontSize: theme.typography.fontSize.sm,
                    fontWeight: theme.typography.fontWeight.semibold,
                    boxShadow: theme.shadows.glow.red,
                  }}
                >
                  🎯 {flow.sink}
                </div>
              </div>

              <div style={{ marginTop: theme.spacing.md, fontSize: theme.typography.fontSize.sm, color: theme.colors.text.secondary }}>
                <strong>File:</strong> {flow.file} | <strong>Lines:</strong> {flow.line_start} - {flow.line_end}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default TaintFlows;




