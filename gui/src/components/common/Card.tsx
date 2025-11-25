import React from 'react';
import { theme } from '../../styles/theme';

interface CardProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  icon?: React.ReactNode;
  className?: string;
  glow?: boolean;
  noBorder?: boolean;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  onClick?: () => void;
}

export const Card: React.FC<CardProps> = ({
  children,
  title,
  subtitle,
  icon,
  className = '',
  glow = false,
  noBorder = false,
  padding = 'md',
  onClick,
}) => {
  const paddingStyles = {
    none: '0',
    sm: theme.spacing.sm,
    md: theme.spacing.md,
    lg: theme.spacing.lg,
  };

  const styles = {
    background: theme.colors.background.card,
    backdropFilter: 'blur(10px)',
    border: noBorder ? 'none' : `1px solid ${theme.colors.border.primary}`,
    borderRadius: theme.borderRadius.lg,
    padding: paddingStyles[padding],
    transition: theme.transitions.normal,
    cursor: onClick ? 'pointer' : 'default',
    boxShadow: glow ? theme.shadows.glow.cyan : 'none',
  };

  const handleMouseEnter = (e: React.MouseEvent<HTMLDivElement>) => {
    if (onClick) {
      e.currentTarget.style.background = theme.colors.background.cardHover;
      e.currentTarget.style.borderColor = theme.colors.border.glow;
      e.currentTarget.style.boxShadow = theme.shadows.glow.green;
    }
  };

  const handleMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
    if (onClick) {
      e.currentTarget.style.background = theme.colors.background.card;
      e.currentTarget.style.borderColor = theme.colors.border.primary;
      e.currentTarget.style.boxShadow = glow ? theme.shadows.glow.cyan : 'none';
    }
  };

  return (
    <div
      className={`glass-card ${className}`}
      style={styles}
      onClick={onClick}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {(title || subtitle || icon) && (
        <div style={{ marginBottom: theme.spacing.md, display: 'flex', alignItems: 'center', gap: theme.spacing.sm }}>
          {icon && <div style={{ color: theme.colors.accent.cyan, fontSize: '1.5rem' }}>{icon}</div>}
          <div style={{ flex: 1 }}>
            {title && (
              <h3 style={{ 
                fontFamily: theme.typography.fontFamily.display,
                fontSize: theme.typography.fontSize.lg,
                fontWeight: theme.typography.fontWeight.semibold,
                color: theme.colors.text.primary,
                marginBottom: subtitle ? '0.25rem' : 0,
              }}>
                {title}
              </h3>
            )}
            {subtitle && (
              <p style={{ 
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.secondary,
                margin: 0,
              }}>
                {subtitle}
              </p>
            )}
          </div>
        </div>
      )}
      {children}
    </div>
  );
};




