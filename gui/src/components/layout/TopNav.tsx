import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { theme } from '../../styles/theme';
import { useStore } from '../../utils/store';
import { FileUploader } from '../common/FileUploader';

const tabs = [
  { id: 'dashboard', label: 'Executive Dashboard', path: '/' },
  { id: 'file-tree', label: 'File Tree', path: '/file-tree' },
  { id: 'findings', label: 'All Findings', path: '/findings' },
  { id: 'dangerous-functions', label: 'Dangerous Functions', path: '/dangerous-functions' },
  { id: 'secrets', label: 'Secrets', path: '/secrets' },
  { id: 'taint-sources', label: 'Taint Sources', path: '/taint-sources' },
  { id: 'taint-flows', label: 'Taint Flow Graph', path: '/taint-flows' },
  { id: 'validation', label: 'Validation Issues', path: '/validation' },
  { id: 'crypto', label: 'Cryptography', path: '/crypto' },
  { id: 'auth', label: 'Authentication', path: '/auth' },
  { id: 'framework', label: 'Framework Security', path: '/framework' },
  { id: 'quality', label: 'Code Quality', path: '/quality' },
  { id: 'antipatterns', label: 'Anti-Patterns', path: '/antipatterns' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', path: '/vulnerabilities' },
  { id: 'settings', label: 'Settings', path: '/settings' },
  { id: 'about', label: 'About', path: '/about' },
];

export const TopNav: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { analysisData, clearAnalysisData } = useStore();
  const [showFileUploader, setShowFileUploader] = useState(false);

  const currentPath = location.pathname;

  const handleTabClick = (path: string) => {
    navigate(path);
  };

  const handleNewAnalysis = () => {
    setShowFileUploader(!showFileUploader);
  };

  const handleExitToHome = () => {
    if (confirm('Are you sure you want to exit to the home screen? Current analysis will be cleared.')) {
      clearAnalysisData();
      navigate('/');
    }
  };

  return (
    <nav style={{
      background: theme.colors.background.secondary,
      borderBottom: `1px solid ${theme.colors.border.primary}`,
      padding: `${theme.spacing.md} ${theme.spacing.lg}`,
      position: 'sticky',
      top: 0,
      zIndex: theme.zIndex.sticky,
      backdropFilter: 'blur(10px)',
    }}>
      {/* Logo and Title */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: theme.spacing.md,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.md }}>
          <div style={{
            fontSize: '2rem',
            background: `linear-gradient(135deg, ${theme.colors.accent.cyan}, ${theme.colors.accent.green})`,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            fontFamily: theme.typography.fontFamily.display,
            fontWeight: theme.typography.fontWeight.bold,
          }}>
            🛡️ CodeX
          </div>
          <div style={{
            padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
            background: theme.colors.background.tertiary,
            border: `1px solid ${theme.colors.border.secondary}`,
            borderRadius: theme.borderRadius.sm,
            fontSize: theme.typography.fontSize.xs,
            color: theme.colors.accent.green,
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}>
            Security Code Analysis
          </div>
        </div>

        {/* Project Info */}
        {analysisData && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing.lg,
            fontSize: theme.typography.fontSize.sm,
            color: theme.colors.text.secondary,
          }}>
            <div>
              <span style={{ color: theme.colors.text.tertiary }}>Project:</span>{' '}
              <span style={{ color: theme.colors.text.primary, fontWeight: theme.typography.fontWeight.semibold }}>
                {analysisData.metadata.project_name || 'Unknown'}
              </span>
            </div>
            <div>
              <span style={{ color: theme.colors.text.tertiary }}>Files:</span>{' '}
              <span style={{ color: theme.colors.accent.cyan }}>{analysisData.files_scanned.length}</span>
            </div>
            <div>
              <span style={{ color: theme.colors.text.tertiary }}>Issues:</span>{' '}
              <span style={{ color: theme.colors.severity.critical }}>{analysisData.summary.total_issues}</span>
            </div>
            <div style={{ display: 'flex', gap: theme.spacing.sm }}>
              <button
                onClick={handleNewAnalysis}
                style={{
                  padding: `${theme.spacing.xs} ${theme.spacing.md}`,
                  background: theme.colors.accent.green,
                  color: theme.colors.background.primary,
                  border: 'none',
                  borderRadius: theme.borderRadius.sm,
                  fontSize: theme.typography.fontSize.sm,
                  fontWeight: theme.typography.fontWeight.semibold,
                  cursor: 'pointer',
                  transition: theme.transitions.fast,
                  boxShadow: theme.shadows.glow.green,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'scale(1.05)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'scale(1)';
                }}
              >
                📂 Load New Analysis
              </button>
              
              <button
                onClick={handleExitToHome}
                style={{
                  padding: `${theme.spacing.xs} ${theme.spacing.md}`,
                  background: theme.colors.background.tertiary,
                  color: theme.colors.accent.cyan,
                  border: `1px solid ${theme.colors.border.primary}`,
                  borderRadius: theme.borderRadius.sm,
                  fontSize: theme.typography.fontSize.sm,
                  fontWeight: theme.typography.fontWeight.semibold,
                  cursor: 'pointer',
                  transition: theme.transitions.fast,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'scale(1.05)';
                  e.currentTarget.style.borderColor = theme.colors.accent.cyan;
                  e.currentTarget.style.boxShadow = theme.shadows.glow.cyan;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'scale(1)';
                  e.currentTarget.style.borderColor = theme.colors.border.primary;
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                🏠 Exit to Home
              </button>
            </div>
          </div>
        )}
      </div>

      {/* File Uploader Modal */}
      {showFileUploader && (
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
            zIndex: theme.zIndex.modal,
            padding: theme.spacing.lg,
          }}
          onClick={() => setShowFileUploader(false)}
        >
          <div
            style={{
              background: theme.colors.background.secondary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.lg,
              padding: theme.spacing.xl,
              maxWidth: '500px',
              width: '100%',
              boxShadow: theme.shadows.glow.cyan,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: theme.spacing.lg }}>
              <h3 style={{
                fontSize: theme.typography.fontSize.xl,
                fontWeight: theme.typography.fontWeight.semibold,
                color: theme.colors.accent.cyan,
              }}>
                Load New Analysis
              </h3>
              <button
                onClick={() => setShowFileUploader(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: theme.colors.text.secondary,
                  fontSize: theme.typography.fontSize['2xl'],
                  cursor: 'pointer',
                  padding: theme.spacing.xs,
                }}
              >
                ×
              </button>
            </div>
            
            <FileUploader onFileLoad={() => {
              setShowFileUploader(false);
              navigate('/');
            }} />
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div style={{
        display: 'flex',
        gap: theme.spacing.xs,
        overflowX: 'auto',
        paddingBottom: theme.spacing.xs,
      }}>
        {tabs.map((tab) => {
          const isActive = currentPath === tab.path;
          return (
            <button
              key={tab.id}
              onClick={() => handleTabClick(tab.path)}
              style={{
                padding: `${theme.spacing.sm} ${theme.spacing.md}`,
                background: isActive
                  ? `linear-gradient(135deg, ${theme.colors.accent.cyan}20, ${theme.colors.accent.blue}20)`
                  : 'transparent',
                border: `1px solid ${isActive ? theme.colors.accent.cyan : theme.colors.border.tertiary}`,
                borderRadius: theme.borderRadius.md,
                color: isActive ? theme.colors.accent.cyan : theme.colors.text.secondary,
                fontSize: theme.typography.fontSize.sm,
                fontWeight: theme.typography.fontWeight.medium,
                cursor: 'pointer',
                transition: theme.transitions.fast,
                whiteSpace: 'nowrap',
                fontFamily: theme.typography.fontFamily.primary,
                boxShadow: isActive ? theme.shadows.glow.cyan : 'none',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.borderColor = theme.colors.border.primary;
                  e.currentTarget.style.color = theme.colors.text.primary;
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.borderColor = theme.colors.border.tertiary;
                  e.currentTarget.style.color = theme.colors.text.secondary;
                }
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </nav>
  );
};

