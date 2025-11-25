// Core Data Types for Security Analysis Platform

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN' | 'UNKNOWN';

// Project Metadata
export interface ProjectMetadata {
  project_path: string;
  scan_time: string;
  analyzer_version: string;
  project_name?: string;
}

// File Information
export interface FileInfo {
  path: string;
  language: string;
  lines: number;
  size: number;
  risk_score?: number;
  vulnerability_count?: number;
}

// Dangerous Function Finding
export interface DangerousFunction {
  function: string;
  category: string;
  language: string;
  file: string;
  line: number;
  context: string;
  severity?: SeverityLevel;
  description?: string;
}

// Secret Finding
export interface SecretFinding {
  type: string;
  file: string;
  line: number;
  context: string;
  entropy?: number;
  severity: SeverityLevel;
  value?: string;
}

// Taint Source
export interface TaintSource {
  source: string;
  type: string;
  file: string;
  line: number;
  context: string;
  severity: SeverityLevel;
}

// Taint Flow
export interface TaintFlow {
  source: string;
  sink: string;
  flow_path: string[];
  file: string;
  line_start: number;
  line_end: number;
  severity: SeverityLevel;
}

// Validation Issue
export interface ValidationIssue {
  type: string;
  message: string;
  file: string;
  filepath?: string;
  line: number;
  context: string;
  severity: SeverityLevel;
  recommendation?: string;
}

// Cryptography Issue
export interface CryptoIssue {
  type: string;
  message: string;
  file: string;
  filepath?: string;
  line: number;
  context: string;
  severity: SeverityLevel;
  recommendation?: string;
}

// Authentication Issue
export interface AuthIssue {
  type: string;
  message: string;
  file: string;
  filepath?: string;
  line: number;
  context: string;
  severity: SeverityLevel;
  category?: string;
}

// Framework Issue
export interface FrameworkIssue {
  framework: string;
  type: string;
  message: string;
  file: string;
  filepath?: string;
  line: number;
  context: string;
  severity: SeverityLevel;
  recommendation?: string;
}

// Quality Issue
export interface QualityIssue {
  type: string;
  message: string;
  file: string;
  line: number;
  context: string;
  severity: SeverityLevel;
}

// Anti-Pattern
export interface AntiPattern {
  pattern: string;
  type: string;
  file: string;
  line: number;
  context: string;
  severity: SeverityLevel;
  recommendation?: string;
}

// Vulnerability
export interface Vulnerability {
  id: string;
  package_name: string;
  version: string;
  ecosystem: string;
  severity: SeverityLevel;
  summary: string;
  details?: string;
  cvss_score?: number;
  cve_ids?: string[];
  aliases?: string[];
  published_date?: string;
  fixed_versions?: string[];
  references?: string[];
  exploit_available?: boolean;
}

// Vulnerability Scan Result
export interface VulnerabilityScanResult {
  total_dependencies: number;
  vulnerable_packages: number;
  total_vulnerabilities: number;
  severity_breakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  packages: Array<{
    name: string;
    version: string;
    ecosystem: string;
    vulnerabilities: Vulnerability[];
  }>;
  scan_duration?: number;
}

// Summary
export interface AnalysisSummary {
  dangerous_functions_count: number;
  secrets_count: number;
  taint_sources_count: number;
  validation_issues_count: number;
  crypto_issues_count: number;
  auth_issues_count: number;
  framework_issues_count: number;
  quality_issues_count: number;
  antipattern_count: number;
  vulnerability_count: number;
  files_scanned: number;
  total_issues: number;
  risk_level: RiskLevel;
}

// Risk Assessment
export interface RiskAssessment {
  risk_level: RiskLevel;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score?: number;
}

// Complete Analysis Result
export interface AnalysisResult {
  metadata: ProjectMetadata;
  dangerous_functions: DangerousFunction[];
  secrets: SecretFinding[];
  taint_analysis: TaintSource[];
  taint_flows?: TaintFlow[];
  validation_issues: ValidationIssue[];
  crypto_issues: CryptoIssue[];
  auth_issues: AuthIssue[];
  framework_issues: FrameworkIssue[];
  quality_issues: {
    [key: string]: QualityIssue[];
  };
  antipatterns: {
    [key: string]: AntiPattern[];
  };
  vulnerability_scan?: VulnerabilityScanResult;
  files_scanned: FileInfo[];
  summary: AnalysisSummary;
  risk_level: RiskLevel;
}

// Unified Finding (for consolidated table)
export interface UnifiedFinding {
  id: string;
  category: string;
  vulnerability: string;
  file: string;
  line: number;
  severity: SeverityLevel;
  description: string;
  recommendation?: string;
  context?: string;
  type?: string;
}

// Chart Data Types
export interface ChartDataPoint {
  name: string;
  value: number;
  color?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  label?: string;
}

// Export Options
export interface ExportOptions {
  format: 'json' | 'csv' | 'pdf' | 'png';
  includeCharts?: boolean;
  includeMetadata?: boolean;
  sections?: string[];
}

// Filter Options
export interface FilterOptions {
  severity?: SeverityLevel[];
  files?: string[];
  categories?: string[];
  searchTerm?: string;
  dateRange?: {
    start: Date;
    end: Date;
  };
}

// Report Configuration (for share/select feature)
export interface ReportConfig {
  selectedSections: {
    executiveSummary: boolean;
    dangerousFunctions: boolean;
    secrets: boolean;
    taintAnalysis: boolean;
    validationIssues: boolean;
    cryptoIssues: boolean;
    authIssues: boolean;
    frameworkIssues: boolean;
    qualityIssues: boolean;
    antipatterns: boolean;
    vulnerabilities: boolean;
  };
  includeCharts: boolean;
  includeCodeSnippets: boolean;
  includeRecommendations: boolean;
  exportFormat: 'pdf' | 'json' | 'html';
}

// Navigation Tab
export interface NavigationTab {
  id: string;
  label: string;
  icon: string;
  path: string;
  badge?: number;
}


