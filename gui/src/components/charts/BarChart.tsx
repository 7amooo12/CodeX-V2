import React from 'react';
import { BarChart as RechartsBar, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { theme } from '../../styles/theme';

interface BarChartProps {
  data: Array<{ name: string; value: number; [key: string]: any }>;
  title?: string;
  height?: number;
  dataKey?: string;
  color?: string;
  horizontal?: boolean;
}

export const BarChart: React.FC<BarChartProps> = ({
  data,
  title,
  height = 300,
  dataKey = 'value',
  color = theme.colors.accent.cyan,
  horizontal = false,
}) => {
  return (
    <div>
      {title && (
        <h4 style={{
          fontSize: theme.typography.fontSize.lg,
          fontWeight: theme.typography.fontWeight.semibold,
          color: theme.colors.text.primary,
          marginBottom: theme.spacing.md,
        }}>
          {title}
        </h4>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <RechartsBar 
          data={data}
          layout={horizontal ? 'vertical' : 'horizontal'}
        >
          <CartesianGrid 
            strokeDasharray="3 3" 
            stroke={theme.colors.border.tertiary}
          />
          <XAxis 
            dataKey={horizontal ? dataKey : 'name'}
            stroke={theme.colors.text.secondary}
            type={horizontal ? 'number' : 'category'}
          />
          <YAxis 
            dataKey={horizontal ? 'name' : undefined}
            stroke={theme.colors.text.secondary}
            type={horizontal ? 'category' : 'number'}
          />
          <Tooltip 
            contentStyle={{
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
            }}
          />
          <Bar 
            dataKey={horizontal ? dataKey : dataKey} 
            fill={color}
          />
        </RechartsBar>
      </ResponsiveContainer>
    </div>
  );
};




