/**
 * API Client for Analyzer Backend
 * =================================
 * Communication layer between React frontend and Flask backend
 */

// @ts-ignore - Vite env variables
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:5000/api';

export interface AnalysisConfig {
  project_path: string;
  max_workers?: number;
  max_files?: number;
  output_format?: 'json' | 'pdf' | 'both';
}

export interface AnalysisStatus {
  analysis_id: string;
  status: 'initializing' | 'running' | 'completed' | 'error';
  progress: number;
  current_step: string;
  steps_completed: number;
  total_steps: number;
  logs: Array<{
    timestamp: string;
    level: string;
    message: string;
  }>;
  error?: string;
  start_time: string;
  end_time?: string;
  has_results: boolean;
}

export interface PathValidation {
  valid: boolean;
  path?: string;
  estimated_files?: string | number;
  error?: string;
}

export interface SystemInfo {
  platform: string;
  python_version: string;
  cpu_count: number;
  recommended_threads: number;
}

/**
 * Check if API server is healthy
 */
export async function checkHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();
    return data.status === 'healthy';
  } catch (error) {
    console.error('Health check failed:', error);
    return false;
  }
}

/**
 * Validate project path
 */
export async function validatePath(path: string): Promise<PathValidation> {
  try {
    const response = await fetch(`${API_BASE_URL}/validate-path`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ path }),
    });
    
    return await response.json();
  } catch (error) {
    return {
      valid: false,
      error: 'Failed to connect to backend server',
    };
  }
}

/**
 * Start new analysis
 */
export async function startAnalysis(config: AnalysisConfig): Promise<{ analysis_id: string; status: string }> {
  const response = await fetch(`${API_BASE_URL}/start-analysis`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(config),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to start analysis');
  }
  
  return await response.json();
}

/**
 * Get analysis status
 */
export async function getAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
  const response = await fetch(`${API_BASE_URL}/analysis/${analysisId}/status`);
  
  if (!response.ok) {
    throw new Error('Failed to fetch analysis status');
  }
  
  return await response.json();
}

/**
 * Get analysis results
 */
export async function getAnalysisResults(analysisId: string): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/analysis/${analysisId}/results`);
  
  if (!response.ok) {
    throw new Error('Analysis not completed yet');
  }
  
  return await response.json();
}

/**
 * Download analysis file
 */
export function downloadAnalysisFile(analysisId: string, fileType: 'json' | 'pdf'): string {
  return `${API_BASE_URL}/analysis/${analysisId}/download/${fileType}`;
}

/**
 * Get system information
 */
export async function getSystemInfo(): Promise<SystemInfo> {
  const response = await fetch(`${API_BASE_URL}/system-info`);
  return await response.json();
}

/**
 * Browse directory structure
 */
export interface BrowseItem {
  name: string;
  path: string;
  type: 'directory' | 'file' | 'drive';
  is_dir: boolean;
  size?: number;
  modified?: number;
}

export interface BrowseResult {
  current_path: string;
  parent_path: string | null;
  items: BrowseItem[];
  total_items?: number;
}

export async function browseDirectory(path: string = ''): Promise<BrowseResult> {
  const response = await fetch(`${API_BASE_URL}/browse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ path }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to browse directory');
  }
  
  return await response.json();
}

/**
 * Get user's home directory
 */
export async function getHomeDirectory(): Promise<{ home_directory: string; exists: boolean }> {
  const response = await fetch(`${API_BASE_URL}/get-home-directory`);
  return await response.json();
}

/**
 * Read file content for preview
 */
export interface FileLineData {
  line_number: number;
  content: string;
  is_highlighted: boolean;
  is_context: boolean;
}

export interface FilePreviewData {
  file_path: string;
  language: string;
  total_lines: number;
  lines: FileLineData[];
  highlight_start: number;
  highlight_end: number;
  context_start: number;
  context_end: number;
}

export async function readFileContent(
  filePath: string,
  startLine: number,
  endLine?: number,
  contextLines: number = 10
): Promise<FilePreviewData> {
  const response = await fetch(`${API_BASE_URL}/read-file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      file_path: filePath,
      start_line: startLine,
      end_line: endLine,
      context_lines: contextLines,
    }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to read file');
  }
  
  return await response.json();
}

/**
 * Poll analysis status until completion
 */
export async function pollAnalysisStatus(
  analysisId: string,
  onUpdate: (status: AnalysisStatus) => void,
  interval: number = 1000
): Promise<AnalysisStatus> {
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const status = await getAnalysisStatus(analysisId);
        onUpdate(status);
        
        if (status.status === 'completed') {
          resolve(status);
        } else if (status.status === 'error') {
          reject(new Error(status.error || 'Analysis failed'));
        } else {
          setTimeout(poll, interval);
        }
      } catch (error) {
        reject(error);
      }
    };
    
    poll();
  });
}

