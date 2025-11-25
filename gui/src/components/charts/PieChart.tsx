import React from 'react';
import { PieChart as RechartsPie, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { theme } from '../../styles/theme';

interface PieChartProps {
  data: Array<{ name: string; value: number; color?: string }>;
  title?: string;
  height?: number;
  donut?: boolean;
}

export const PieChart: React.FC<PieChartProps> = ({
  data,
  title,
  height = 300,
  donut = false,
}) => {
  const COLORS = [
    theme.colors.severity.critical,
    theme.colors.severity.high,
    theme.colors.severity.medium,
    theme.colors.severity.low,
    theme.colors.accent.cyan,
    theme.colors.accent.green,
    theme.colors.accent.blue,
    theme.colors.accent.purple,
  ];

  return (
    <div>
      {title && (
        <h4 style={{
          fontSize: theme.typography.fontSize.lg,
          fontWeight: theme.typography.fontWeight.semibold,
          color: theme.colors.text.primary,
          marginBottom: theme.spacing.md,
          textAlign: 'center',
        }}>
          {title}
        </h4>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <RechartsPie>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
            outerRadius={donut ? 80 : 100}
            innerRadius={donut ? 50 : 0}
            fill="#8884d8"
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.color || COLORS[index % COLORS.length]} 
              />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.md,
              color: theme.colors.text.primary,
            }}
          />
          <Legend 
            wrapperStyle={{
              color: theme.colors.text.primary,
            }}
          />
        </RechartsPie>
      </ResponsiveContainer>
    </div>
  );
};




