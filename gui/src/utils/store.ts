import { create } from 'zustand';
import { AnalysisResult, FilterOptions, ReportConfig } from '../types';

interface AppState {
  // Analysis Data
  analysisData: AnalysisResult | null;
  setAnalysisData: (data: AnalysisResult) => void;
  clearAnalysisData: () => void;
  
  // Loading States
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  
  // Filter State
  filters: FilterOptions;
  setFilters: (filters: FilterOptions) => void;
  resetFilters: () => void;
  
  // Report Configuration (for share/select feature)
  reportConfig: ReportConfig;
  setReportConfig: (config: Partial<ReportConfig>) => void;
  resetReportConfig: () => void;
  
  // UI State
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  
  // Selected File (for file tree)
  selectedFile: string | null;
  setSelectedFile: (file: string | null) => void;
  
  // Theme
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
}

const defaultReportConfig: ReportConfig = {
  selectedSections: {
    executiveSummary: true,
    dangerousFunctions: true,
    secrets: true,
    taintAnalysis: true,
    validationIssues: true,
    cryptoIssues: true,
    authIssues: true,
    frameworkIssues: true,
    qualityIssues: true,
    antipatterns: true,
    vulnerabilities: true,
  },
  includeCharts: true,
  includeCodeSnippets: true,
  includeRecommendations: true,
  exportFormat: 'pdf',
};

export const useStore = create<AppState>((set) => ({
  // Initial State
  analysisData: null,
  isLoading: false,
  filters: {},
  reportConfig: defaultReportConfig,
  sidebarOpen: true,
  currentTab: 'dashboard',
  selectedFile: null,
  theme: 'dark',
  
  // Actions
  setAnalysisData: (data) => set({ analysisData: data }),
  clearAnalysisData: () => set({ analysisData: null }),
  setIsLoading: (loading) => set({ isLoading: loading }),
  
  setFilters: (filters) => set((state) => ({ 
    filters: { ...state.filters, ...filters } 
  })),
  resetFilters: () => set({ filters: {} }),
  
  setReportConfig: (config) => set((state) => ({ 
    reportConfig: { ...state.reportConfig, ...config } 
  })),
  resetReportConfig: () => set({ reportConfig: defaultReportConfig }),
  
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  setCurrentTab: (tab) => set({ currentTab: tab }),
  setSelectedFile: (file) => set({ selectedFile: file }),
  setTheme: (theme) => set({ theme }),
}));



