import React, { useState, useEffect } from 'react';
import { theme } from '../../styles/theme';
import { Card } from './Card';
import { Button } from './Button';
import { pollAnalysisStatus, getAnalysisResults, downloadAnalysisFile, type AnalysisStatus } from '../../utils/api';
import { adaptAnalysisData, ensureSummary } from '../../utils/dataAdapter';
import { useStore } from '../../utils/store';
import { useNavigate } from 'react-router-dom';

interface AnalysisProgressProps {
  analysisId: string;
  onCancel: () => void;
}

export const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ analysisId, onCancel }) => {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { setAnalysisData } = useStore();
  const navigate = useNavigate();

  useEffect(() => {
    // Start polling for status updates
    const startPolling = async () => {
      try {
        await pollAnalysisStatus(analysisId, (updatedStatus) => {
          setStatus(updatedStatus);
        });

        // Analysis completed - load results
        const results = await getAnalysisResults(analysisId);
        const adaptedData = adaptAnalysisData(results);
        const finalData = ensureSummary(adaptedData);
        
        setAnalysisData(finalData);
        
        // Show success message
        setTimeout(() => {
          navigate('/');
        }, 2000);
        
      } catch (err: any) {
        setError(err.message || 'Analysis failed');
      }
    };

    startPolling();
  }, [analysisId, setAnalysisData, navigate]);

  const getProgressColor = () => {
    if (error || status?.status === 'error') return theme.colors.severity.critical;
    if (status?.status === 'completed') return theme.colors.severity.low;
    return theme.colors.accent.cyan;
  };

  const getStatusIcon = () => {
    if (error || status?.status === 'error') return '❌';
    if (status?.status === 'completed') return '✅';
    return '⚡';
  };

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
      <Card glow padding="xl" style={{ maxWidth: '800px', width: '100%' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: theme.spacing.xl }}>
          <div style={{ fontSize: '4rem', marginBottom: theme.spacing.md }}>
            {getStatusIcon()}
          </div>
          <h2
            style={{
              fontSize: theme.typography.fontSize['3xl'],
              fontWeight: theme.typography.fontWeight.bold,
              color: theme.colors.text.primary,
              marginBottom: theme.spacing.sm,
            }}
          >
            {error || status?.status === 'error'
              ? 'Analysis Failed'
              : status?.status === 'completed'
              ? 'Analysis Complete!'
              : 'Running Analysis...'}
          </h2>
          <p
            style={{
              fontSize: theme.typography.fontSize.base,
              color: theme.colors.text.secondary,
            }}
          >
            Analysis ID: <code style={{ 
              fontFamily: theme.typography.fontFamily.mono,
              color: theme.colors.accent.cyan 
            }}>{analysisId}</code>
          </p>
        </div>

        {/* Error Message */}
        {error && (
          <div
            style={{
              marginBottom: theme.spacing.lg,
              padding: theme.spacing.md,
              background: `${theme.colors.severity.critical}20`,
              border: `1px solid ${theme.colors.severity.critical}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.severity.critical,
            }}
          >
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Progress Bar */}
        {status && !error && (
          <>
            <div style={{ marginBottom: theme.spacing.lg }}>
              <div
                style={{
                  width: '100%',
                  height: '8px',
                  background: theme.colors.background.tertiary,
                  borderRadius: theme.borderRadius.full,
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${status.progress}%`,
                    height: '100%',
                    background: `linear-gradient(90deg, ${getProgressColor()}, ${theme.colors.accent.green})`,
                    transition: 'width 0.3s ease',
                    boxShadow: `0 0 10px ${getProgressColor()}`,
                  }}
                />
              </div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginTop: theme.spacing.xs,
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.secondary,
                }}
              >
                <span>{status.progress}%</span>
                <span>
                  Step {status.steps_completed} of {status.total_steps}
                </span>
              </div>
            </div>

            {/* Current Step */}
            <div
              style={{
                marginBottom: theme.spacing.lg,
                padding: theme.spacing.md,
                background: theme.colors.background.tertiary,
                borderRadius: theme.borderRadius.md,
                border: `1px solid ${theme.colors.border.primary}`,
              }}
            >
              <div
                style={{
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.tertiary,
                  marginBottom: theme.spacing.xs,
                }}
              >
                Current Step:
              </div>
              <div
                style={{
                  fontSize: theme.typography.fontSize.base,
                  color: theme.colors.accent.cyan,
                  fontWeight: theme.typography.fontWeight.medium,
                }}
              >
                {status.current_step || 'Initializing...'}
              </div>
            </div>

            {/* Logs */}
            <div style={{ marginBottom: theme.spacing.lg }}>
              <h4
                style={{
                  fontSize: theme.typography.fontSize.base,
                  fontWeight: theme.typography.fontWeight.semibold,
                  color: theme.colors.text.primary,
                  marginBottom: theme.spacing.sm,
                }}
              >
                📝 Activity Log
              </h4>
              <div
                style={{
                  maxHeight: '200px',
                  overflowY: 'auto',
                  background: theme.colors.background.secondary,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.md,
                  padding: theme.spacing.sm,
                }}
              >
                {status.logs.length === 0 ? (
                  <div
                    style={{
                      fontSize: theme.typography.fontSize.sm,
                      color: theme.colors.text.tertiary,
                      textAlign: 'center',
                      padding: theme.spacing.md,
                    }}
                  >
                    No logs yet...
                  </div>
                ) : (
                  status.logs.map((log, index) => (
                    <div
                      key={index}
                      style={{
                        fontSize: theme.typography.fontSize.xs,
                        fontFamily: theme.typography.fontFamily.mono,
                        color:
                          log.level === 'error'
                            ? theme.colors.severity.critical
                            : log.level === 'warning'
                            ? theme.colors.severity.high
                            : log.level === 'success'
                            ? theme.colors.severity.low
                            : theme.colors.text.secondary,
                        marginBottom: theme.spacing.xs,
                        padding: theme.spacing.xs,
                        borderLeft: `2px solid ${
                          log.level === 'error'
                            ? theme.colors.severity.critical
                            : log.level === 'success'
                            ? theme.colors.severity.low
                            : 'transparent'
                        }`,
                        paddingLeft: theme.spacing.sm,
                      }}
                    >
                      <span style={{ color: theme.colors.text.tertiary }}>
                        [{new Date(log.timestamp).toLocaleTimeString()}]
                      </span>{' '}
                      {log.message}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Completion Message */}
            {status.status === 'completed' && (
              <div
                style={{
                  marginBottom: theme.spacing.lg,
                  padding: theme.spacing.md,
                  background: `${theme.colors.severity.low}20`,
                  border: `1px solid ${theme.colors.severity.low}`,
                  borderRadius: theme.borderRadius.md,
                  textAlign: 'center',
                }}
              >
                <div
                  style={{
                    fontSize: theme.typography.fontSize.lg,
                    fontWeight: theme.typography.fontWeight.semibold,
                    color: theme.colors.severity.low,
                    marginBottom: theme.spacing.sm,
                  }}
                >
                  🎉 Analysis completed successfully!
                </div>
                <p style={{ fontSize: theme.typography.fontSize.sm, color: theme.colors.text.secondary }}>
                  Redirecting to dashboard...
                </p>
              </div>
            )}
          </>
        )}

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: theme.spacing.md, justifyContent: 'center' }}>
          {status?.status === 'completed' && (
            <>
              <Button
                variant="primary"
                size="md"
                icon="📊"
                onClick={() => navigate('/')}
              >
                View Dashboard
              </Button>
              <Button
                variant="secondary"
                size="md"
                icon="📥"
                onClick={() => {
                  window.open(downloadAnalysisFile(analysisId, 'json'), '_blank');
                }}
              >
                Download JSON
              </Button>
            </>
          )}
          
          {(status?.status === 'error' || error) && (
            <Button
              variant="secondary"
              size="md"
              icon="↩️"
              onClick={onCancel}
            >
              Back to Home
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
};


