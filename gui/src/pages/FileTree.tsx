import React, { useMemo, useState } from 'react';
import { useStore } from '../utils/store';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Badge, EmptyState } from '../components/common';
import { theme } from '../styles/theme';
import { getFileName, getDirectory } from '../utils/helpers';

const FileTree: React.FC = () => {
  const { analysisData, setSelectedFile } = useStore();
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());

  // Build file tree structure with risk indicators
  const fileTree = useMemo(() => {
    if (!analysisData) return null;

    const tree: Record<string, any> = {};
    const fileRisks: Record<string, { count: number; maxSeverity: string }> = {};

    // Calculate risk for each file
    [...analysisData.dangerous_functions, ...analysisData.secrets, ...analysisData.taint_analysis].forEach(item => {
      const file = item.file;
      if (!fileRisks[file]) {
        fileRisks[file] = { count: 0, maxSeverity: 'LOW' };
      }
      fileRisks[file].count += 1;

      const severity = item.severity || 'LOW';
      const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      if (severityOrder.indexOf(severity) < severityOrder.indexOf(fileRisks[file].maxSeverity)) {
        fileRisks[file].maxSeverity = severity;
      }
    });

    // Build tree structure
    Object.keys(fileRisks).forEach(filePath => {
      const parts = filePath.split(/[\\/]/);
      let current = tree;

      parts.forEach((part, index) => {
        if (!current[part]) {
          current[part] = {
            name: part,
            path: parts.slice(0, index + 1).join('/'),
            isFile: index === parts.length - 1,
            children: {},
            ...fileRisks[filePath],
          };
        }
        current = current[part].children;
      });
    });

    return tree;
  }, [analysisData]);

  const toggleFolder = (path: string) => {
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const getRiskColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: theme.colors.severity.critical,
      HIGH: theme.colors.severity.high,
      MEDIUM: theme.colors.severity.medium,
      LOW: theme.colors.severity.low,
    };
    return colors[severity] || theme.colors.severity.low;
  };

  const renderTree = (node: any, level = 0) => {
    return Object.values(node).map((item: any) => {
      const isExpanded = expandedFolders.has(item.path);
      const hasChildren = Object.keys(item.children || {}).length > 0;

      return (
        <div key={item.path} style={{ marginLeft: `${level * 20}px` }}>
          <div
            onClick={() => {
              if (hasChildren) {
                toggleFolder(item.path);
              } else {
                setSelectedFile(item.path);
              }
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing.sm,
              padding: theme.spacing.sm,
              borderRadius: theme.borderRadius.sm,
              cursor: 'pointer',
              transition: theme.transitions.fast,
              background: 'transparent',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = theme.colors.background.cardHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
            }}
          >
            {/* Expand/Collapse Icon */}
            {hasChildren && (
              <span style={{ fontSize: '0.8rem', color: theme.colors.text.secondary }}>
                {isExpanded ? '▼' : '▶'}
              </span>
            )}

            {/* File/Folder Icon */}
            <span style={{ fontSize: '1.2rem' }}>
              {item.isFile ? '📄' : '📁'}
            </span>

            {/* Name */}
            <span style={{
              flex: 1,
              color: theme.colors.text.primary,
              fontFamily: theme.typography.fontFamily.mono,
              fontSize: theme.typography.fontSize.sm,
            }}>
              {item.name}
            </span>

            {/* Risk Indicator */}
            {item.count > 0 && (
              <>
                <div
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: getRiskColor(item.maxSeverity),
                    boxShadow: `0 0 10px ${getRiskColor(item.maxSeverity)}`,
                  }}
                  title={`${item.maxSeverity} risk`}
                />
                <Badge
                  severity={item.maxSeverity as any}
                  size="sm"
                  variant="subtle"
                >
                  {item.count}
                </Badge>
              </>
            )}
          </div>

          {/* Children */}
          {hasChildren && isExpanded && renderTree(item.children, level + 1)}
        </div>
      );
    });
  };

  if (!analysisData || !fileTree) {
    return (
      <EmptyState
        icon="📁"
        title="No Files to Display"
        description="No analysis data available"
      />
    );
  }

  return (
    <div>
      <PageHeader
        title="File Tree Hierarchy"
        subtitle="Interactive file explorer with risk indicators"
        icon="📁"
        stats={[
          { label: 'Total Files', value: analysisData.files_scanned.length },
          { label: 'Critical', value: analysisData.summary.secrets_count, color: theme.colors.severity.critical },
          { label: 'High', value: analysisData.summary.dangerous_functions_count, color: theme.colors.severity.high },
          { label: 'Medium', value: analysisData.summary.validation_issues_count, color: theme.colors.severity.medium },
        ]}
      />

      <Card title="Project Structure" subtitle="Click on files to view details">
        <div style={{
          maxHeight: '70vh',
          overflowY: 'auto',
          padding: theme.spacing.sm,
        }}>
          {renderTree(fileTree)}
        </div>
      </Card>
    </div>
  );
};

export default FileTree;




