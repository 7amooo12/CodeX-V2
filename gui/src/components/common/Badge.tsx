import React from 'react';
import { SeverityLevel } from '../../types';
import { getSeverityColor } from '../../utils/helpers';
import { theme } from '../../styles/theme';

interface BadgeProps {
  severity?: SeverityLevel;
  color?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
  glow?: boolean;
  variant?: 'solid' | 'outline' | 'subtle';
}

export const Badge: React.FC<BadgeProps> = ({
  severity,
  color,
  children,
  size = 'md',
  glow = false,
  variant = 'solid',
}) => {
  const badgeColor = severity ? getSeverityColor(severity) : (color || theme.colors.accent.cyan);

  const sizeStyles = {
    sm: {
      padding: '0.25rem 0.5rem',
      fontSize: theme.typography.fontSize.xs,
    },
    md: {
      padding: '0.375rem 0.75rem',
      fontSize: theme.typography.fontSize.sm,
    },
    lg: {
      padding: '0.5rem 1rem',
      fontSize: theme.typography.fontSize.base,
    },
  };

  const variantStyles = {
    solid: {
      background: badgeColor,
      color: severity === 'LOW' || severity === 'MEDIUM' ? theme.colors.background.primary : theme.colors.text.primary,
      border: 'none',
    },
    outline: {
      background: 'transparent',
      color: badgeColor,
      border: `1px solid ${badgeColor}`,
    },
    subtle: {
      background: `${badgeColor}20`,
      color: badgeColor,
      border: `1px solid ${badgeColor}40`,
    },
  };

  const styles = {
    ...sizeStyles[size],
    ...variantStyles[variant],
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: theme.borderRadius.sm,
    fontFamily: theme.typography.fontFamily.primary,
    fontWeight: theme.typography.fontWeight.semibold,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
    whiteSpace: 'nowrap' as const,
    transition: theme.transitions.fast,
    boxShadow: glow ? `0 0 10px ${badgeColor}80` : 'none',
  };

  return (
    <span style={styles}>
      {children}
    </span>
  );
};




