import React from 'react';
import { theme } from '../../styles/theme';

interface LoadingSpinnerProps {
  size?: number;
  message?: string;
  fullScreen?: boolean;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 40,
  message = 'Loading...',
  fullScreen = false,
}) => {
  const containerStyles: React.CSSProperties = fullScreen ? {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    background: theme.colors.background.overlay,
    zIndex: theme.zIndex.modal,
  } : {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: theme.spacing.xl,
  };

  const spinnerStyles: React.CSSProperties = {
    width: `${size}px`,
    height: `${size}px`,
    border: `3px solid ${theme.colors.background.tertiary}`,
    borderTop: `3px solid ${theme.colors.accent.cyan}`,
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  };

  return (
    <div style={containerStyles}>
      <div style={spinnerStyles} />
      {message && (
        <p style={{
          marginTop: theme.spacing.md,
          fontSize: theme.typography.fontSize.base,
          color: theme.colors.text.secondary,
          fontFamily: theme.typography.fontFamily.primary,
        }}>
          {message}
        </p>
      )}
    </div>
  );
};




