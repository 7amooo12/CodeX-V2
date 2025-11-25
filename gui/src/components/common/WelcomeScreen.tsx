import React, { useState } from 'react';
import { theme } from '../../styles/theme';
import { Card } from './Card';
import { FileUploader } from './FileUploader';
import { Button } from './Button';
import { StartNewAnalysis } from './StartNewAnalysis';
import { AnalysisProgress } from './AnalysisProgress';
import { useStore } from '../../utils/store';
import { adaptAnalysisData, ensureSummary } from '../../utils/dataAdapter';

export const WelcomeScreen: React.FC = () => {
  const { setAnalysisData } = useStore();
  const [activeTab, setActiveTab] = useState<'load' | 'new'>('load');
  const [runningAnalysisId, setRunningAnalysisId] = useState<string | null>(null);

  const loadDemoData = async () => {
    try {
      const response = await fetch('/data/demo-data.json');
      if (response.ok) {
        const rawData = await response.json();
        // Demo data is already in correct format, but still adapt for consistency
        const adaptedData = adaptAnalysisData(rawData);
        const finalData = ensureSummary(adaptedData);
        setAnalysisData(finalData);
      }
    } catch (error) {
      console.error('Error loading demo data:', error);
    }
  };

  const handleAnalysisStart = (analysisId: string) => {
    setRunningAnalysisId(analysisId);
  };

  const handleCancelAnalysis = () => {
    setRunningAnalysisId(null);
  };

  // If analysis is running, show progress screen
  if (runningAnalysisId) {
    return <AnalysisProgress analysisId={runningAnalysisId} onCancel={handleCancelAnalysis} />;
  }

  return (
    <div
      style={{
        minHeight: '80vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: theme.spacing.xl,
      }}
    >
      <div style={{ maxWidth: '800px', width: '100%' }}>
        {/* Hero Section */}
        <div style={{ textAlign: 'center', marginBottom: theme.spacing['2xl'] }}>
          <div
            style={{
              fontSize: '4rem',
              marginBottom: theme.spacing.lg,
            }}
          >
            🛡️
          </div>
          <h1
            style={{
              fontSize: theme.typography.fontSize['4xl'],
              fontWeight: theme.typography.fontWeight.bold,
              fontFamily: theme.typography.fontFamily.display,
              background: `linear-gradient(135deg, ${theme.colors.accent.cyan}, ${theme.colors.accent.green})`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              marginBottom: theme.spacing.md,
            }}
          >
            CodeX Analysis Platform
          </h1>
          <p
            style={{
              fontSize: theme.typography.fontSize.xl,
              color: theme.colors.text.secondary,
              marginBottom: theme.spacing.md,
            }}
          >
            Security Analysis Dashboard
          </p>
          <p
            style={{
              fontSize: theme.typography.fontSize.base,
              color: theme.colors.text.tertiary,
            }}
          >
            Load your security analysis results or try the demo
          </p>
        </div>

        {/* Tab Selector */}
        <div
          style={{
            display: 'flex',
            gap: theme.spacing.sm,
            marginBottom: theme.spacing.lg,
            justifyContent: 'center',
          }}
        >
          <button
            onClick={() => setActiveTab('load')}
            style={{
              padding: `${theme.spacing.md} ${theme.spacing.xl}`,
              background:
                activeTab === 'load'
                  ? `linear-gradient(135deg, ${theme.colors.accent.cyan}40, ${theme.colors.accent.blue}40)`
                  : theme.colors.background.secondary,
              border: `2px solid ${
                activeTab === 'load' ? theme.colors.accent.cyan : theme.colors.border.primary
              }`,
              borderRadius: theme.borderRadius.lg,
              color: activeTab === 'load' ? theme.colors.accent.cyan : theme.colors.text.secondary,
              fontSize: theme.typography.fontSize.base,
              fontWeight: theme.typography.fontWeight.semibold,
              cursor: 'pointer',
              transition: theme.transitions.fast,
              boxShadow: activeTab === 'load' ? theme.shadows.glow.cyan : 'none',
            }}
          >
            📂 Load Existing Analysis
          </button>
          <button
            onClick={() => setActiveTab('new')}
            style={{
              padding: `${theme.spacing.md} ${theme.spacing.xl}`,
              background:
                activeTab === 'new'
                  ? `linear-gradient(135deg, ${theme.colors.accent.green}40, ${theme.colors.accent.cyan}40)`
                  : theme.colors.background.secondary,
              border: `2px solid ${
                activeTab === 'new' ? theme.colors.accent.green : theme.colors.border.primary
              }`,
              borderRadius: theme.borderRadius.lg,
              color: activeTab === 'new' ? theme.colors.accent.green : theme.colors.text.secondary,
              fontSize: theme.typography.fontSize.base,
              fontWeight: theme.typography.fontWeight.semibold,
              cursor: 'pointer',
              transition: theme.transitions.fast,
              boxShadow: activeTab === 'new' ? theme.shadows.glow.green : 'none',
            }}
          >
            🚀 Start New Analysis
          </button>
        </div>

        {/* Main Action Card */}
        {activeTab === 'load' ? (
          <Card glow padding="lg" style={{ marginBottom: theme.spacing.lg }}>
            <div style={{ marginBottom: theme.spacing.xl }}>
              <h3
                style={{
                  fontSize: theme.typography.fontSize.xl,
                  fontWeight: theme.typography.fontWeight.semibold,
                  color: theme.colors.text.primary,
                  marginBottom: theme.spacing.sm,
                  textAlign: 'center',
                }}
              >
                Load Analysis Results
              </h3>
              <p
                style={{
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.secondary,
                  textAlign: 'center',
                  marginBottom: theme.spacing.lg,
                }}
              >
                Click below to browse and select your analysis JSON file
              </p>
            </div>

            <FileUploader />
          </Card>
        ) : (
          <StartNewAnalysis onAnalysisStart={handleAnalysisStart} />
        )}

        {/* Quick Actions */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: theme.spacing.md,
            marginBottom: theme.spacing.xl,
          }}
        >
          <Card padding="md">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2rem', marginBottom: theme.spacing.sm }}>📊</div>
              <Button variant="secondary" size="md" onClick={loadDemoData} fullWidth>
                Load Demo Data
              </Button>
              <p
                style={{
                  marginTop: theme.spacing.sm,
                  fontSize: theme.typography.fontSize.xs,
                  color: theme.colors.text.tertiary,
                }}
              >
                Try with sample data
              </p>
            </div>
          </Card>

          <Card padding="md">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2rem', marginBottom: theme.spacing.sm }}>📖</div>
              <Button
                variant="secondary"
                size="md"
                onClick={() => window.open('/documentation.html', '_blank')}
                fullWidth
              >
                View Documentation
              </Button>
              <p
                style={{
                  marginTop: theme.spacing.sm,
                  fontSize: theme.typography.fontSize.xs,
                  color: theme.colors.text.tertiary,
                }}
              >
                Setup guide
              </p>
            </div>
          </Card>
        </div>

        {/* How to Generate */}
        <Card padding="lg">
          <h4
            style={{
              fontSize: theme.typography.fontSize.lg,
              fontWeight: theme.typography.fontWeight.semibold,
              color: theme.colors.accent.cyan,
              marginBottom: theme.spacing.md,
            }}
          >
            🚀 How to Generate Analysis File
          </h4>

          <div
            style={{
              background: theme.colors.background.tertiary,
              padding: theme.spacing.md,
              borderRadius: theme.borderRadius.md,
              marginBottom: theme.spacing.md,
            }}
          >
            <p
              style={{
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.secondary,
                marginBottom: theme.spacing.sm,
              }}
            >
              <strong style={{ color: theme.colors.text.primary }}>Step 1:</strong> Run the analyzer
              on your project
            </p>
            <pre
              style={{
                background: theme.colors.background.secondary,
                padding: theme.spacing.sm,
                borderRadius: theme.borderRadius.sm,
                fontFamily: theme.typography.fontFamily.mono,
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.accent.green,
                overflow: 'auto',
              }}
            >
              python comprehensive_analyzer.py . -json
            </pre>
          </div>

          <div
            style={{
              background: theme.colors.background.tertiary,
              padding: theme.spacing.md,
              borderRadius: theme.borderRadius.md,
            }}
          >
            <p
              style={{
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.secondary,
                marginBottom: theme.spacing.sm,
              }}
            >
              <strong style={{ color: theme.colors.text.primary }}>Step 2:</strong> Load the generated
              file
            </p>
            <p
              style={{
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.tertiary,
                fontFamily: theme.typography.fontFamily.mono,
              }}
            >
              📂 output/comprehensive_analysis.json
            </p>
          </div>
        </Card>

        {/* Features Grid */}
        <div
          style={{
            marginTop: theme.spacing.xl,
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: theme.spacing.md,
          }}
        >
          {[
            { icon: '🎯', title: 'Risk Assessment', desc: 'Real-time risk scoring' },
            { icon: '📊', title: 'Visualizations', desc: 'Interactive charts' },
            { icon: '🔍', title: 'Deep Analysis', desc: '12+ security modules' },
            { icon: '📥', title: 'Export Reports', desc: 'CSV, JSON, PDF' },
            { icon: '🌊', title: 'Taint Analysis', desc: 'Data flow tracking' },
            { icon: '🔑', title: 'Secret Detection', desc: 'Credential scanning' },
          ].map((feature, index) => (
            <div
              key={index}
              style={{
                padding: theme.spacing.md,
                background: theme.colors.background.card,
                border: `1px solid ${theme.colors.border.primary}`,
                borderRadius: theme.borderRadius.md,
                textAlign: 'center',
                transition: theme.transitions.fast,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = theme.colors.border.glow;
                e.currentTarget.style.background = theme.colors.background.cardHover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = theme.colors.border.primary;
                e.currentTarget.style.background = theme.colors.background.card;
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: theme.spacing.xs }}>{feature.icon}</div>
              <h5
                style={{
                  fontSize: theme.typography.fontSize.sm,
                  fontWeight: theme.typography.fontWeight.semibold,
                  color: theme.colors.text.primary,
                  marginBottom: theme.spacing.xs,
                }}
              >
                {feature.title}
              </h5>
              <p
                style={{
                  fontSize: theme.typography.fontSize.xs,
                  color: theme.colors.text.tertiary,
                }}
              >
                {feature.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

