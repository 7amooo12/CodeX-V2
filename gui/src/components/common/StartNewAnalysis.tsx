import React, { useState, useEffect } from 'react';
import { theme } from '../../styles/theme';
import { Card } from './Card';
import { Button } from './Button';
import { FileBrowser } from './FileBrowser';
import { validatePath, startAnalysis, getSystemInfo, type SystemInfo } from '../../utils/api';

interface StartNewAnalysisProps {
  onAnalysisStart: (analysisId: string) => void;
}

export const StartNewAnalysis: React.FC<StartNewAnalysisProps> = ({ onAnalysisStart }) => {
  const [projectPath, setProjectPath] = useState('');
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [maxWorkers, setMaxWorkers] = useState(4);
  const [maxFiles, setMaxFiles] = useState(0);
  const [outputFormat, setOutputFormat] = useState<'json' | 'pdf' | 'both'>('json');
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [showFileBrowser, setShowFileBrowser] = useState(false);

  useEffect(() => {
    // Load system info
    getSystemInfo().then(info => {
      setSystemInfo(info);
      setMaxWorkers(info.recommended_threads);
    }).catch(console.error);
  }, []);

  const handlePathChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setProjectPath(e.target.value);
    setValidationResult(null);
  };

  const handleValidatePath = async () => {
    if (!projectPath.trim()) {
      alert('Please enter a project path');
      return;
    }

    setIsValidating(true);
    try {
      const result = await validatePath(projectPath);
      setValidationResult(result);
    } catch (error) {
      setValidationResult({
        valid: false,
        error: 'Failed to validate path. Make sure the API server is running.',
      });
    } finally {
      setIsValidating(false);
    }
  };

  const handleStartAnalysis = async () => {
    if (!validationResult?.valid) {
      alert('Please validate the path first');
      return;
    }

    setIsStarting(true);
    try {
      const result = await startAnalysis({
        project_path: validationResult.path,
        max_workers: maxWorkers,
        max_files: maxFiles > 0 ? maxFiles : undefined,
        output_format: outputFormat,
      });

      onAnalysisStart(result.analysis_id);
    } catch (error: any) {
      alert(`Failed to start analysis: ${error.message}`);
    } finally {
      setIsStarting(false);
    }
  };

  const handleBrowseFolder = () => {
    setShowFileBrowser(true);
  };

  const handlePathSelected = (path: string) => {
    setProjectPath(path);
    setValidationResult(null);
    // Auto-validate after selection
    setTimeout(() => {
      handleValidatePath();
    }, 100);
  };

  return (
    <>
      {/* File Browser Modal */}
      {showFileBrowser && (
        <FileBrowser
          onSelectPath={handlePathSelected}
          onClose={() => setShowFileBrowser(false)}
        />
      )}

      <Card glow padding="lg">
        <div style={{ marginBottom: theme.spacing.xl }}>
        <h3
          style={{
            fontSize: theme.typography.fontSize.xl,
            fontWeight: theme.typography.fontWeight.semibold,
            color: theme.colors.accent.green,
            marginBottom: theme.spacing.sm,
            textAlign: 'center',
          }}
        >
          🚀 Start New Analysis
        </h3>
        <p
          style={{
            fontSize: theme.typography.fontSize.sm,
            color: theme.colors.text.secondary,
            textAlign: 'center',
            marginBottom: theme.spacing.lg,
          }}
        >
          Analyze your project directly from the interface
        </p>
      </div>

      {/* Project Path Input */}
      <div style={{ marginBottom: theme.spacing.lg }}>
        <label
          style={{
            display: 'block',
            fontSize: theme.typography.fontSize.sm,
            fontWeight: theme.typography.fontWeight.medium,
            color: theme.colors.text.primary,
            marginBottom: theme.spacing.xs,
          }}
        >
          Project Path
        </label>
        <div style={{ display: 'flex', gap: theme.spacing.sm }}>
          <input
            type="text"
            value={projectPath}
            onChange={handlePathChange}
            placeholder="C:\Users\YourName\project or /home/user/project"
            style={{
              flex: 1,
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
              fontSize: theme.typography.fontSize.sm,
              fontFamily: theme.typography.fontFamily.mono,
            }}
          />
          <Button
            variant="secondary"
            size="md"
            onClick={handleBrowseFolder}
            icon="📁"
          >
            Browse
          </Button>
          <Button
            variant="primary"
            size="md"
            onClick={handleValidatePath}
            disabled={isValidating || !projectPath.trim()}
          >
            {isValidating ? 'Validating...' : 'Validate'}
          </Button>
        </div>
        
        {/* Validation Result */}
        {validationResult && (
          <div
            style={{
              marginTop: theme.spacing.sm,
              padding: theme.spacing.sm,
              background: validationResult.valid
                ? `${theme.colors.severity.low}20`
                : `${theme.colors.severity.critical}20`,
              border: `1px solid ${
                validationResult.valid
                  ? theme.colors.severity.low
                  : theme.colors.severity.critical
              }`,
              borderRadius: theme.borderRadius.sm,
              fontSize: theme.typography.fontSize.sm,
            }}
          >
            {validationResult.valid ? (
              <>
                <div style={{ color: theme.colors.severity.low, fontWeight: 'bold' }}>
                  ✅ Valid Path
                </div>
                <div style={{ color: theme.colors.text.secondary, marginTop: theme.spacing.xs }}>
                  Path: {validationResult.path}
                </div>
                <div style={{ color: theme.colors.text.secondary }}>
                  Estimated files: {validationResult.estimated_files}
                </div>
              </>
            ) : (
              <div style={{ color: theme.colors.severity.critical }}>
                ❌ {validationResult.error}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Configuration Options */}
      {validationResult?.valid && (
        <div
          style={{
            marginBottom: theme.spacing.lg,
            padding: theme.spacing.md,
            background: theme.colors.background.tertiary,
            borderRadius: theme.borderRadius.md,
          }}
        >
          <h4
            style={{
              fontSize: theme.typography.fontSize.base,
              fontWeight: theme.typography.fontWeight.semibold,
              color: theme.colors.text.primary,
              marginBottom: theme.spacing.md,
            }}
          >
            ⚙️ Configuration
          </h4>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing.md }}>
            {/* Max Workers */}
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.secondary,
                  marginBottom: theme.spacing.xs,
                }}
              >
                Worker Threads
              </label>
              <input
                type="number"
                min="1"
                max="32"
                value={maxWorkers}
                onChange={(e) => setMaxWorkers(parseInt(e.target.value) || 4)}
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.background.secondary,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.sm,
                  color: theme.colors.text.primary,
                  fontSize: theme.typography.fontSize.sm,
                }}
              />
              {systemInfo && (
                <div
                  style={{
                    fontSize: theme.typography.fontSize.xs,
                    color: theme.colors.text.tertiary,
                    marginTop: theme.spacing.xs,
                  }}
                >
                  Recommended: {systemInfo.recommended_threads} (CPU: {systemInfo.cpu_count})
                </div>
              )}
            </div>

            {/* Max Files */}
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.secondary,
                  marginBottom: theme.spacing.xs,
                }}
              >
                Max Files (0 = unlimited)
              </label>
              <input
                type="number"
                min="0"
                max="100000"
                value={maxFiles}
                onChange={(e) => setMaxFiles(parseInt(e.target.value) || 0)}
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.background.secondary,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.sm,
                  color: theme.colors.text.primary,
                  fontSize: theme.typography.fontSize.sm,
                }}
              />
            </div>
          </div>

          {/* Output Format */}
          <div style={{ marginTop: theme.spacing.md }}>
            <label
              style={{
                display: 'block',
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.secondary,
                marginBottom: theme.spacing.xs,
              }}
            >
              Output Format
            </label>
            <div style={{ display: 'flex', gap: theme.spacing.sm }}>
              {(['json', 'pdf', 'both'] as const).map((format) => (
                <button
                  key={format}
                  onClick={() => setOutputFormat(format)}
                  style={{
                    flex: 1,
                    padding: theme.spacing.sm,
                    background:
                      outputFormat === format
                        ? `linear-gradient(135deg, ${theme.colors.accent.cyan}30, ${theme.colors.accent.blue}30)`
                        : theme.colors.background.secondary,
                    border: `1px solid ${
                      outputFormat === format
                        ? theme.colors.accent.cyan
                        : theme.colors.border.primary
                    }`,
                    borderRadius: theme.borderRadius.sm,
                    color:
                      outputFormat === format
                        ? theme.colors.accent.cyan
                        : theme.colors.text.secondary,
                    fontSize: theme.typography.fontSize.sm,
                    fontWeight: theme.typography.fontWeight.medium,
                    cursor: 'pointer',
                    transition: theme.transitions.fast,
                  }}
                >
                  {format.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Start Button */}
      {validationResult?.valid && (
        <Button
          variant="primary"
          size="lg"
          icon="▶️"
          onClick={handleStartAnalysis}
          disabled={isStarting}
          fullWidth
        >
          {isStarting ? 'Starting Analysis...' : 'Start Comprehensive Analysis'}
        </Button>
      )}

      {/* Info Box */}
      <div
        style={{
          marginTop: theme.spacing.md,
          padding: theme.spacing.sm,
          background: `${theme.colors.accent.blue}10`,
          border: `1px solid ${theme.colors.accent.blue}30`,
          borderRadius: theme.borderRadius.sm,
          fontSize: theme.typography.fontSize.xs,
          color: theme.colors.text.tertiary,
        }}
      >
        💡 <strong>Tip:</strong> Click "Browse" to navigate your local file system visually, or manually
        enter a path. Make sure the API server is running:{' '}
        <code
          style={{
            background: theme.colors.background.secondary,
            padding: '2px 6px',
            borderRadius: '3px',
            fontFamily: theme.typography.fontFamily.mono,
            color: theme.colors.accent.green,
          }}
        >
          python analyzer_api.py
        </code>
      </div>
      </Card>
    </>
  );
};

