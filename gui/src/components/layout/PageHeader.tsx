import React from 'react';
import { theme } from '../../styles/theme';
import { Button } from '../common';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  stats?: Array<{
    label: string;
    value: string | number;
    color?: string;
  }>;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  icon,
  actions,
  stats,
}) => {
  return (
    <div style={{
      marginBottom: theme.spacing.xl,
      paddingBottom: theme.spacing.lg,
      borderBottom: `1px solid ${theme.colors.border.primary}`,
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        marginBottom: stats ? theme.spacing.lg : 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.md }}>
          {icon && (
            <div style={{
              fontSize: '2.5rem',
              color: theme.colors.accent.cyan,
            }}>
              {icon}
            </div>
          )}
          <div>
            <h1 style={{
              fontSize: theme.typography.fontSize['3xl'],
              fontWeight: theme.typography.fontWeight.bold,
              fontFamily: theme.typography.fontFamily.display,
              background: `linear-gradient(135deg, ${theme.colors.accent.cyan}, ${theme.colors.accent.green})`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              marginBottom: subtitle ? theme.spacing.xs : 0,
            }}>
              {title}
            </h1>
            {subtitle && (
              <p style={{
                fontSize: theme.typography.fontSize.base,
                color: theme.colors.text.secondary,
                margin: 0,
              }}>
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {actions && (
          <div style={{ display: 'flex', gap: theme.spacing.sm }}>
            {actions}
          </div>
        )}
      </div>

      {stats && stats.length > 0 && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${Math.min(stats.length, 6)}, 1fr)`,
          gap: theme.spacing.md,
        }}>
          {stats.map((stat, index) => (
            <div
              key={index}
              style={{
                padding: theme.spacing.md,
                background: theme.colors.background.card,
                border: `1px solid ${theme.colors.border.primary}`,
                borderRadius: theme.borderRadius.md,
                textAlign: 'center',
              }}
            >
              <div style={{
                fontSize: theme.typography.fontSize['2xl'],
                fontWeight: theme.typography.fontWeight.bold,
                color: stat.color || theme.colors.accent.cyan,
                marginBottom: theme.spacing.xs,
              }}>
                {stat.value}
              </div>
              <div style={{
                fontSize: theme.typography.fontSize.sm,
                color: theme.colors.text.secondary,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}>
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};




