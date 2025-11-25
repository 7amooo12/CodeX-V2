import React, { useState, useEffect, useRef } from 'react';
import { theme } from '../../styles/theme';
import { Card } from './Card';
import { Button } from './Button';
import { LoadingSpinner } from './LoadingSpinner';
import { readFileContent, type FilePreviewData, type FileLineData } from '../../utils/api';

interface FilePreviewModalProps {
  filePath: string;
  line: number;
  endLine?: number;
  title?: string;
  description?: string;
  severity?: string;
  onClose: () => void;
}

export const FilePreviewModal: React.FC<FilePreviewModalProps> = ({
  filePath,
  line,
  endLine,
  title,
  description,
  severity,
  onClose,
}) => {
  const [fileData, setFileData] = useState<FilePreviewData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const highlightRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadFileContent();
  }, [filePath, line]);

  useEffect(() => {
    // Auto-scroll to highlighted line
    if (highlightRef.current && fileData) {
      setTimeout(() => {
        highlightRef.current?.scrollIntoView({
          behavior: 'smooth',
          block: 'center',
        });
      }, 100);
    }
  }, [fileData]);

  const loadFileContent = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await readFileContent(filePath, line, endLine, 10);
      setFileData(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load file');
    } finally {
      setIsLoading(false);
    }
  };

  const getSeverityColor = (sev?: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return theme.colors.severity.critical;
      case 'HIGH':
        return theme.colors.severity.high;
      case 'MEDIUM':
        return theme.colors.severity.medium;
      case 'LOW':
        return theme.colors.severity.low;
      default:
        return theme.colors.accent.cyan;
    }
  };

  const getLanguageLabel = (lang: string) => {
    const labels: Record<string, string> = {
      python: '🐍 Python',
      javascript: '🟨 JavaScript',
      typescript: '🔷 TypeScript',
      java: '☕ Java',
      csharp: '#️⃣ C#',
      php: '🐘 PHP',
      go: '🔵 Go',
      rust: '🦀 Rust',
      ruby: '💎 Ruby',
      cpp: '⚙️ C++',
      c: '⚙️ C',
    };
    return labels[lang] || `📄 ${lang}`;
  };

  const syntaxHighlight = (content: string, language: string) => {
    // Simple but effective syntax highlighting
    let highlighted = content;

    // Escape HTML
    highlighted = highlighted
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Keywords
    const keywords = [
      'if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var',
      'class', 'import', 'export', 'from', 'def', 'async', 'await', 'try', 'catch',
      'throw', 'new', 'this', 'super', 'extends', 'implements', 'interface', 'type',
      'public', 'private', 'protected', 'static', 'void', 'int', 'string', 'boolean',
    ];

    keywords.forEach((kw) => {
      const regex = new RegExp(`\\b(${kw})\\b`, 'g');
      highlighted = highlighted.replace(
        regex,
        `<span style="color: ${theme.colors.accent.purple}">${kw}</span>`
      );
    });

    // Strings
    highlighted = highlighted.replace(
      /(['"`])((?:\\.|(?!\1).)*?)\1/g,
      `<span style="color: ${theme.colors.accent.green}">$&</span>`
    );

    // Numbers
    highlighted = highlighted.replace(
      /\b(\d+\.?\d*)\b/g,
      `<span style="color: ${theme.colors.accent.yellow}">$1</span>`
    );

    // Comments
    highlighted = highlighted.replace(
      /(\/\/.*$|#.*$)/gm,
      `<span style="color: ${theme.colors.text.tertiary}; font-style: italic">$1</span>`
    );

    highlighted = highlighted.replace(
      /(\/\*[\s\S]*?\*\/)/g,
      `<span style="color: ${theme.colors.text.tertiary}; font-style: italic">$1</span>`
    );

    // Function calls
    highlighted = highlighted.replace(
      /\b([a-zA-Z_]\w*)\s*\(/g,
      `<span style="color: ${theme.colors.accent.cyan}">$1</span>(`
    );

    return highlighted;
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: theme.colors.background.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: theme.zIndex.modal + 1,
        padding: theme.spacing.lg,
      }}
      onClick={onClose}
    >
      <Card
        glow
        padding="none"
        style={{
          maxWidth: '1400px',
          width: '100%',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: theme.spacing.lg,
            borderBottom: `2px solid ${theme.colors.border.primary}`,
            background: theme.colors.background.tertiary,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.md, marginBottom: theme.spacing.sm }}>
                <h3
                  style={{
                    fontSize: theme.typography.fontSize['2xl'],
                    fontWeight: theme.typography.fontWeight.bold,
                    color: theme.colors.accent.cyan,
                    margin: 0,
                  }}
                >
                  🔍 File Preview
                </h3>
                {severity && (
                  <div
                    style={{
                      padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                      background: `${getSeverityColor(severity)}20`,
                      border: `1px solid ${getSeverityColor(severity)}`,
                      borderRadius: theme.borderRadius.sm,
                      fontSize: theme.typography.fontSize.xs,
                      fontWeight: theme.typography.fontWeight.bold,
                      color: getSeverityColor(severity),
                      textTransform: 'uppercase',
                    }}
                  >
                    {severity}
                  </div>
                )}
              </div>

              {title && (
                <div
                  style={{
                    fontSize: theme.typography.fontSize.base,
                    color: theme.colors.text.primary,
                    marginBottom: theme.spacing.xs,
                    fontWeight: theme.typography.fontWeight.semibold,
                  }}
                >
                  {title}
                </div>
              )}

              {description && (
                <div
                  style={{
                    fontSize: theme.typography.fontSize.sm,
                    color: theme.colors.text.secondary,
                    marginBottom: theme.spacing.sm,
                  }}
                >
                  {description}
                </div>
              )}

              <div
                style={{
                  display: 'flex',
                  gap: theme.spacing.lg,
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.tertiary,
                  fontFamily: theme.typography.fontFamily.mono,
                }}
              >
                <div>
                  📁 <span style={{ color: theme.colors.text.secondary }}>{filePath}</span>
                </div>
                <div>
                  📍 Line {line}{endLine && endLine !== line && `-${endLine}`}
                </div>
                {fileData && (
                  <div>
                    {getLanguageLabel(fileData.language)}
                  </div>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                color: theme.colors.text.secondary,
                fontSize: theme.typography.fontSize['3xl'],
                cursor: 'pointer',
                padding: theme.spacing.xs,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>
        </div>

        {/* Content */}
        <div
          style={{
            flex: 1,
            overflow: 'auto',
            background: theme.colors.background.secondary,
            minHeight: 0, // Important for flex scrolling
          }}
          className="custom-scrollbar"
        >
          {isLoading ? (
            <div style={{ padding: theme.spacing['2xl'], textAlign: 'center' }}>
              <LoadingSpinner message="Loading file content..." size={50} />
            </div>
          ) : error ? (
            <div
              style={{
                padding: theme.spacing.xl,
                textAlign: 'center',
                color: theme.colors.severity.critical,
              }}
            >
              <div style={{ fontSize: '3rem', marginBottom: theme.spacing.md }}>⚠️</div>
              <div style={{ fontSize: theme.typography.fontSize.lg, marginBottom: theme.spacing.sm }}>
                Error Loading File
              </div>
              <div style={{ fontSize: theme.typography.fontSize.sm, color: theme.colors.text.secondary }}>
                {error}
              </div>
            </div>
          ) : fileData ? (
            <div style={{ display: 'flex', minHeight: '100%' }}>
              {/* Line Numbers */}
              <div
                style={{
                  background: theme.colors.background.tertiary,
                  borderRight: `2px solid ${theme.colors.border.primary}`,
                  padding: `${theme.spacing.md} ${theme.spacing.sm}`,
                  textAlign: 'right',
                  fontFamily: theme.typography.fontFamily.mono,
                  fontSize: theme.typography.fontSize.sm,
                  color: theme.colors.text.tertiary,
                  userSelect: 'none',
                  minWidth: '60px',
                  position: 'sticky',
                  left: 0,
                  zIndex: 1,
                }}
              >
                {fileData.lines.map((lineData) => (
                  <div
                    key={lineData.line_number}
                    style={{
                      height: '24px',
                      lineHeight: '24px',
                      color: lineData.is_highlighted
                        ? theme.colors.accent.cyan
                        : theme.colors.text.tertiary,
                      fontWeight: lineData.is_highlighted
                        ? theme.typography.fontWeight.bold
                        : theme.typography.fontWeight.normal,
                    }}
                  >
                    {lineData.line_number}
                  </div>
                ))}
              </div>

              {/* Code Content */}
              <div
                style={{
                  flex: 1,
                  padding: theme.spacing.md,
                  fontFamily: theme.typography.fontFamily.mono,
                  fontSize: theme.typography.fontSize.sm,
                  lineHeight: '24px',
                  whiteSpace: 'pre',
                  overflowX: 'auto',
                  minWidth: 0, // Important for flex scrolling
                }}
                className="custom-scrollbar"
              >
                {fileData.lines.map((lineData) => (
                  <div
                    key={lineData.line_number}
                    ref={lineData.is_highlighted && lineData.line_number === line ? highlightRef : null}
                    style={{
                      height: '24px',
                      background: lineData.is_highlighted
                        ? `linear-gradient(90deg, ${getSeverityColor(severity)}30, ${getSeverityColor(severity)}10)`
                        : 'transparent',
                      borderLeft: lineData.is_highlighted
                        ? `4px solid ${getSeverityColor(severity)}`
                        : 'none',
                      paddingLeft: lineData.is_highlighted ? theme.spacing.sm : '4px',
                      marginLeft: lineData.is_highlighted ? '-4px' : '0',
                      transition: theme.transitions.fast,
                      position: 'relative',
                    }}
                    dangerouslySetInnerHTML={{
                      __html: syntaxHighlight(lineData.content || ' ', fileData.language),
                    }}
                  />
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: theme.spacing.md,
            borderTop: `2px solid ${theme.colors.border.primary}`,
            background: theme.colors.background.tertiary,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div
            style={{
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.text.tertiary,
            }}
          >
            💡 <strong>Tip:</strong> The highlighted lines show where the vulnerability was detected
          </div>
          <Button variant="secondary" size="md" onClick={onClose}>
            Close
          </Button>
        </div>
      </Card>
    </div>
  );
};

