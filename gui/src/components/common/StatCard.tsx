import React from 'react';
import { Card } from './Card';
import { theme } from '../../styles/theme';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color?: string;
  glow?: boolean;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  color = theme.colors.accent.cyan,
  glow = false,
}) => {
  return (
    <Card padding="lg" glow={glow}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div style={{ flex: 1 }}>
          <p style={{
            fontSize: theme.typography.fontSize.sm,
            color: theme.colors.text.secondary,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            marginBottom: theme.spacing.xs,
          }}>
            {title}
          </p>
          <h2 style={{
            fontSize: theme.typography.fontSize['4xl'],
            fontWeight: theme.typography.fontWeight.bold,
            color: color,
            marginBottom: theme.spacing.xs,
            textShadow: glow ? `0 0 20px ${color}60` : 'none',
          }}>
            {value}
          </h2>
          {subtitle && (
            <p style={{
              fontSize: theme.typography.fontSize.sm,
              color: theme.colors.text.tertiary,
            }}>
              {subtitle}
            </p>
          )}
          {trend && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing.xs,
              marginTop: theme.spacing.sm,
            }}>
              <span style={{
                color: trend.isPositive ? theme.colors.status.success : theme.colors.status.error,
                fontSize: theme.typography.fontSize.sm,
                fontWeight: theme.typography.fontWeight.semibold,
              }}>
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </span>
              <span style={{
                fontSize: theme.typography.fontSize.xs,
                color: theme.colors.text.tertiary,
              }}>
                vs last scan
              </span>
            </div>
          )}
        </div>
        {icon && (
          <div style={{
            fontSize: '3rem',
            color: color,
            opacity: 0.6,
            marginLeft: theme.spacing.md,
          }}>
            {icon}
          </div>
        )}
      </div>
    </Card>
  );
};




