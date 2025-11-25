import { SeverityLevel, RiskLevel } from '../types';
import { theme } from '../styles/theme';

// Severity Color Mapping
export const getSeverityColor = (severity: SeverityLevel): string => {
  const colors: Record<SeverityLevel, string> = {
    CRITICAL: theme.colors.severity.critical,
    HIGH: theme.colors.severity.high,
    MEDIUM: theme.colors.severity.medium,
    LOW: theme.colors.severity.low,
    INFO: theme.colors.severity.info,
  };
  return colors[severity] || theme.colors.text.secondary;
};

// Risk Level Color Mapping
export const getRiskLevelColor = (risk: RiskLevel): string => {
  const colors: Record<RiskLevel, string> = {
    CRITICAL: theme.colors.severity.critical,
    HIGH: theme.colors.severity.high,
    MEDIUM: theme.colors.severity.medium,
    LOW: theme.colors.severity.low,
    CLEAN: theme.colors.accent.green,
    UNKNOWN: theme.colors.text.secondary,
  };
  return colors[risk] || theme.colors.text.secondary;
};

// Format Numbers
export const formatNumber = (num: number): string => {
  return new Intl.NumberFormat('en-US').format(num);
};

// Format File Size
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

// Format Date
export const formatDate = (dateString: string): string => {
  try {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  } catch {
    return dateString;
  }
};

// Format Duration
export const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = (seconds % 60).toFixed(0);
  return `${minutes}m ${secs}s`;
};

// Calculate Risk Score (0-100)
export const calculateRiskScore = (
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  lowCount: number
): number => {
  const score = 
    (criticalCount * 40) +
    (highCount * 20) +
    (mediumCount * 10) +
    (lowCount * 2);
  return Math.min(100, score);
};

// Get File Extension
export const getFileExtension = (filename: string): string => {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
};

// Get File Name from Path
export const getFileName = (path: string): string => {
  return path.split(/[\\/]/).pop() || path;
};

// Get Directory from Path
export const getDirectory = (path: string): string => {
  const parts = path.split(/[\\/]/);
  parts.pop();
  return parts.join('/');
};

// Truncate Text
export const truncate = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
};

// Highlight Syntax (basic)
export const highlightCode = (code: string, language: string): string => {
  // This is a basic implementation - in production you'd use a library like Prism.js
  return code;
};

// Export to JSON
export const exportToJSON = (data: any, filename: string) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { 
    type: 'application/json' 
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

// Export to CSV
export const exportToCSV = (data: any[], filename: string) => {
  if (data.length === 0) return;
  
  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(','),
    ...data.map(row => 
      headers.map(header => {
        const cell = row[header];
        const cellStr = cell === null || cell === undefined ? '' : String(cell);
        // Escape quotes and wrap in quotes if contains comma
        return cellStr.includes(',') ? `"${cellStr.replace(/"/g, '""')}"` : cellStr;
      }).join(',')
    )
  ].join('\n');
  
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

// Debounce Function
export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout | null = null;
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

// Group By Function
export const groupBy = <T>(
  array: T[],
  key: keyof T
): Record<string, T[]> => {
  return array.reduce((result, item) => {
    const groupKey = String(item[key]);
    if (!result[groupKey]) {
      result[groupKey] = [];
    }
    result[groupKey].push(item);
    return result;
  }, {} as Record<string, T[]>);
};

// Sort by Severity
export const sortBySeverity = <T extends { severity: SeverityLevel }>(
  items: T[]
): T[] => {
  const severityOrder: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  
  return [...items].sort((a, b) => 
    severityOrder[a.severity] - severityOrder[b.severity]
  );
};

// Calculate Percentage
export const calculatePercentage = (value: number, total: number): number => {
  if (total === 0) return 0;
  return Math.round((value / total) * 100);
};

// Generate Random ID
export const generateId = (): string => {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

// Deep Clone
export const deepClone = <T>(obj: T): T => {
  return JSON.parse(JSON.stringify(obj));
};

// Check if Object is Empty
export const isEmpty = (obj: any): boolean => {
  if (!obj) return true;
  if (Array.isArray(obj)) return obj.length === 0;
  if (typeof obj === 'object') return Object.keys(obj).length === 0;
  return false;
};




