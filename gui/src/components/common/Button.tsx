import React from 'react';
import { theme } from '../../styles/theme';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'success' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  loading?: boolean;
  fullWidth?: boolean;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  icon,
  loading = false,
  fullWidth = false,
  disabled,
  className = '',
  ...props
}) => {
  const baseStyles = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    fontFamily: theme.typography.fontFamily.primary,
    fontWeight: theme.typography.fontWeight.medium,
    border: 'none',
    borderRadius: theme.borderRadius.md,
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    transition: theme.transitions.normal,
    outline: 'none',
    opacity: disabled || loading ? 0.6 : 1,
    width: fullWidth ? '100%' : 'auto',
  };

  const variantStyles = {
    primary: {
      background: `linear-gradient(135deg, ${theme.colors.accent.cyan}, ${theme.colors.accent.blue})`,
      color: theme.colors.text.primary,
      boxShadow: theme.shadows.glow.cyan,
    },
    secondary: {
      background: theme.colors.background.tertiary,
      color: theme.colors.text.primary,
      border: `1px solid ${theme.colors.border.primary}`,
    },
    danger: {
      background: theme.colors.severity.critical,
      color: theme.colors.text.primary,
      boxShadow: theme.shadows.glow.red,
    },
    success: {
      background: theme.colors.accent.green,
      color: theme.colors.background.primary,
      boxShadow: theme.shadows.glow.green,
    },
    ghost: {
      background: 'transparent',
      color: theme.colors.accent.cyan,
      border: `1px solid ${theme.colors.accent.cyan}`,
    },
  };

  const sizeStyles = {
    sm: {
      padding: '0.5rem 1rem',
      fontSize: theme.typography.fontSize.sm,
    },
    md: {
      padding: '0.75rem 1.5rem',
      fontSize: theme.typography.fontSize.base,
    },
    lg: {
      padding: '1rem 2rem',
      fontSize: theme.typography.fontSize.lg,
    },
  };

  const styles = {
    ...baseStyles,
    ...variantStyles[variant],
    ...sizeStyles[size],
  };

  return (
    <button
      style={styles}
      disabled={disabled || loading}
      className={`btn btn-${variant} ${className}`}
      {...props}
    >
      {loading && (
        <div className="loading-spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} />
      )}
      {!loading && icon && <span>{icon}</span>}
      {children}
    </button>
  );
};




