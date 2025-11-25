/**
 * Data Adapter - Normalizes real analyzer JSON to GUI-expected format
 * Handles differences between actual comprehensive_analyzer.py output and GUI expectations
 */

import { AnalysisResult } from '../types';

export function adaptAnalysisData(rawData: any): AnalysisResult {
  return {
    metadata: rawData.metadata || {},
    
    // Adapt dangerous functions - already correct format
    dangerous_functions: (rawData.dangerous_functions || []).map((item: any) => ({
      function: item.function,
      category: item.category,
      language: item.language,
      file: item.file,
      line: item.line,
      context: item.context || '',
      severity: item.severity || 'MEDIUM',
    })),
    
    // Adapt secrets - add missing fields
    secrets: (rawData.secrets || []).map((item: any) => ({
      type: item.type,
      file: item.file,
      line: item.line,
      context: item.value || item.context || `${item.type} detected`,
      severity: 'CRITICAL', // Secrets are always critical
      entropy: item.entropy || 0,
    })),
    
    // Adapt taint analysis - already correct format
    taint_analysis: (rawData.taint_analysis || []).map((item: any) => ({
      source: item.source,
      type: item.type,
      file: item.file,
      line: item.line,
      context: item.context || '',
      severity: item.severity || 'MEDIUM',
    })),
    
    // Adapt taint flows
    taint_flows: rawData.taint_flows || [],
    
    // Adapt validation issues - fix field names
    validation_issues: (rawData.validation_issues || []).map((item: any) => ({
      type: item.type,
      message: item.message || item.issue || 'Validation issue detected',
      file: item.file,
      filepath: item.file, // Alias
      line: item.line || 0,
      context: item.context || item.message || '',
      severity: item.severity || 'MEDIUM',
      recommendation: item.recommendation || '',
    })),
    
    // Adapt crypto issues - already correct format
    crypto_issues: (rawData.crypto_issues || []).map((item: any) => ({
      type: item.type,
      message: item.message || item.issue || 'Cryptography issue detected',
      file: item.file || item.filepath,
      filepath: item.file || item.filepath, // Alias
      line: item.line || 0,
      context: item.context || '',
      severity: item.severity || 'HIGH',
      recommendation: item.recommendation || '',
    })),
    
    // Adapt auth issues - already correct format
    auth_issues: (rawData.auth_issues || []).map((item: any) => ({
      type: item.type,
      message: item.message || item.issue || 'Authentication issue detected',
      file: item.file || item.filepath,
      filepath: item.file || item.filepath, // Alias
      line: item.line || 0,
      context: item.context || '',
      severity: item.severity || 'HIGH',
      category: item.category || '',
    })),
    
    // Adapt framework issues - fix structure
    framework_issues: (rawData.framework_issues || []).map((item: any) => ({
      framework: item.framework || detectFramework(item.file),
      type: item.type || 'misconfiguration',
      message: item.message || item.issue || 'Framework issue detected',
      file: item.file,
      filepath: item.file, // Alias
      line: item.line || 0,
      context: item.context || '',
      severity: item.severity || 'MEDIUM',
      recommendation: item.recommendation || '',
    })),
    
    // Adapt quality issues - fix structure
    quality_issues: adaptQualityIssues(rawData.quality_issues || {}),
    
    // Adapt antipatterns - fix structure
    antipatterns: adaptAntipatterns(rawData.antipatterns || {}),
    
    // Adapt vulnerability scan - already correct format
    vulnerability_scan: rawData.vulnerability_scan || {
      total_dependencies: 0,
      vulnerable_packages: 0,
      total_vulnerabilities: 0,
      severity_breakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      packages: [],
    },
    
    // Files scanned
    files_scanned: (rawData.files_scanned || []).map((item: any) => ({
      path: item.path || item.file || '',
      language: item.language || 'unknown',
      lines: item.lines || item.line_count || 0,
      size: item.size || 0,
      risk_score: item.risk_score || 0,
      vulnerability_count: item.vulnerability_count || 0,
    })),
    
    // Summary
    summary: {
      dangerous_functions_count: rawData.summary?.dangerous_functions_count || 0,
      secrets_count: rawData.summary?.secrets_count || 0,
      taint_sources_count: rawData.summary?.taint_sources_count || 0,
      validation_issues_count: rawData.summary?.validation_issues_count || 0,
      crypto_issues_count: rawData.summary?.crypto_issues_count || 0,
      auth_issues_count: rawData.summary?.auth_issues_count || 0,
      framework_issues_count: rawData.summary?.framework_issues_count || 0,
      quality_issues_count: rawData.summary?.quality_issues_count || 0,
      antipattern_count: rawData.summary?.antipattern_count || 0,
      vulnerability_count: rawData.summary?.vulnerability_count || 0,
      files_scanned: rawData.summary?.files_scanned || 0,
      total_issues: rawData.summary?.total_issues || 0,
      risk_level: rawData.summary?.risk_level || rawData.risk_level || 'UNKNOWN',
    },
    
    risk_level: rawData.risk_level || rawData.summary?.risk_level || 'UNKNOWN',
  };
}

/**
 * Adapt quality issues structure
 */
function adaptQualityIssues(qualityIssues: any): any {
  const adapted: any = {};
  
  for (const [category, items] of Object.entries(qualityIssues)) {
    if (Array.isArray(items)) {
      adapted[category] = items.map((item: any) => ({
        type: item.type || category,
        message: item.message || item.issue || `${category} detected`,
        file: item.file,
        line: item.line || 0,
        context: item.context || item.message || item.code || '',
        severity: (item.severity || 'LOW').toUpperCase() as any,
      }));
    }
  }
  
  return adapted;
}

/**
 * Adapt antipatterns structure
 */
function adaptAntipatterns(antipatterns: any): any {
  const adapted: any = {};
  
  for (const [category, items] of Object.entries(antipatterns)) {
    if (Array.isArray(items)) {
      adapted[category] = items.map((item: any) => ({
        pattern: item.pattern || item.type || category,
        type: item.type || category,
        file: item.file,
        line: item.line || 0,
        context: item.context || item.message || item.variable_name || `${category} detected`,
        severity: (item.severity || 'MEDIUM').toUpperCase() as any,
        recommendation: item.recommendation || '',
        message: item.message || '',
        variable_name: item.variable_name || '',
      }));
    }
  }
  
  return adapted;
}

/**
 * Detect framework from file path
 */
function detectFramework(filePath: string): string {
  if (!filePath) return 'Unknown';
  
  const path = filePath.toLowerCase();
  
  // Python frameworks
  if (path.includes('django') || path.includes('settings.py')) return 'Django';
  if (path.includes('flask')) return 'Flask';
  if (path.includes('fastapi')) return 'FastAPI';
  
  // JavaScript frameworks
  if (path.includes('express')) return 'Express';
  if (path.includes('react')) return 'React';
  if (path.includes('vue')) return 'Vue';
  if (path.includes('angular')) return 'Angular';
  if (path.includes('next')) return 'Next.js';
  
  // Java frameworks
  if (path.includes('spring')) return 'Spring';
  
  // .NET frameworks
  if (path.includes('.cs') || path.includes('aspnet')) return '.NET';
  
  // PHP frameworks
  if (path.includes('laravel')) return 'Laravel';
  if (path.includes('symfony')) return 'Symfony';
  
  // Detect by file extension
  if (path.endsWith('.py')) return 'Python Framework';
  if (path.endsWith('.js') || path.endsWith('.jsx') || path.endsWith('.ts') || path.endsWith('.tsx')) {
    return 'JavaScript Framework';
  }
  if (path.endsWith('.java')) return 'Java Framework';
  if (path.endsWith('.cs')) return '.NET Framework';
  if (path.endsWith('.php')) return 'PHP Framework';
  
  return 'Unknown';
}

/**
 * Calculate counts if missing from summary
 */
export function ensureSummary(data: AnalysisResult): AnalysisResult {
  if (!data.summary || data.summary.total_issues === 0) {
    const summary = {
      dangerous_functions_count: data.dangerous_functions?.length || 0,
      secrets_count: data.secrets?.length || 0,
      taint_sources_count: data.taint_analysis?.length || 0,
      validation_issues_count: data.validation_issues?.length || 0,
      crypto_issues_count: data.crypto_issues?.length || 0,
      auth_issues_count: data.auth_issues?.length || 0,
      framework_issues_count: data.framework_issues?.length || 0,
      quality_issues_count: Object.values(data.quality_issues || {}).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0),
      antipattern_count: Object.values(data.antipatterns || {}).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0),
      vulnerability_count: data.vulnerability_scan?.total_vulnerabilities || 0,
      files_scanned: data.files_scanned?.length || 0,
      total_issues: 0,
      risk_level: data.risk_level || 'UNKNOWN',
    };
    
    summary.total_issues = 
      summary.dangerous_functions_count +
      summary.secrets_count +
      summary.taint_sources_count +
      summary.validation_issues_count +
      summary.crypto_issues_count +
      summary.auth_issues_count +
      summary.framework_issues_count +
      summary.quality_issues_count +
      summary.antipattern_count +
      summary.vulnerability_count;
    
    data.summary = summary;
  }
  
  return data;
}

