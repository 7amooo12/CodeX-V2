import React from 'react';
import { theme } from '../../styles/theme';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
}) => {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: theme.spacing['3xl'],
      textAlign: 'center',
    }}>
      {icon && (
        <div style={{
          fontSize: '4rem',
          color: theme.colors.text.tertiary,
          marginBottom: theme.spacing.lg,
          opacity: 0.5,
        }}>
          {icon}
        </div>
      )}
      <h3 style={{
        fontSize: theme.typography.fontSize['2xl'],
        fontWeight: theme.typography.fontWeight.semibold,
        color: theme.colors.text.primary,
        marginBottom: theme.spacing.sm,
      }}>
        {title}
      </h3>
      {description && (
        <p style={{
          fontSize: theme.typography.fontSize.base,
          color: theme.colors.text.secondary,
          marginBottom: theme.spacing.lg,
          maxWidth: '500px',
        }}>
          {description}
        </p>
      )}
      {action && (
        <Button variant="primary" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
};




