import React from 'react';
import { LineChart as RechartsLine, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { theme } from '../../styles/theme';

interface LineChartProps {
  data: Array<{ name: string; value: number; [key: string]: any }>;
  title?: string;
  height?: number;
  dataKey?: string;
  color?: string;
}

export const LineChart: React.FC<LineChartProps> = ({
  data,
  title,
  height = 300,
  dataKey = 'value',
  color = theme.colors.accent.green,
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
        <RechartsLine data={data}>
          <CartesianGrid 
            strokeDasharray="3 3" 
            stroke={theme.colors.border.tertiary}
          />
          <XAxis 
            dataKey="name"
            stroke={theme.colors.text.secondary}
          />
          <YAxis 
            stroke={theme.colors.text.secondary}
          />
          <Tooltip 
            contentStyle={{
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
            }}
          />
          <Line 
            type="monotone" 
            dataKey={dataKey} 
            stroke={color}
            strokeWidth={2}
            dot={{ fill: color }}
          />
        </RechartsLine>
      </ResponsiveContainer>
    </div>
  );
};




