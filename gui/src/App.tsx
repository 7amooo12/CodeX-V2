import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { TopNav } from './components/layout/TopNav';
import { useStore } from './utils/store';
import { LoadingSpinner, WelcomeScreen } from './components/common';
import { adaptAnalysisData, ensureSummary } from './utils/dataAdapter';
import './styles/global.css';

// Import Pages (we'll create these next)
import Dashboard from './pages/Dashboard';
import FileTree from './pages/FileTree';
import AllFindings from './pages/AllFindings';
import DangerousFunctions from './pages/DangerousFunctions';
import Secrets from './pages/Secrets';
import TaintSources from './pages/TaintSources';
import TaintFlows from './pages/TaintFlows';
import Validation from './pages/Validation';
import Cryptography from './pages/Cryptography';
import Authentication from './pages/Authentication';
import FrameworkSecurity from './pages/FrameworkSecurity';
import CodeQuality from './pages/CodeQuality';
import AntiPatterns from './pages/AntiPatterns';
import Vulnerabilities from './pages/Vulnerabilities';
import Settings from './pages/Settings';
import About from './pages/About';

function App() {
  const { analysisData, setAnalysisData, isLoading, setIsLoading } = useStore();

  useEffect(() => {
    // Try to auto-load data on mount (but don't show error if not found)
    loadAnalysisData();
  }, []);

  const loadAnalysisData = async () => {
    try {
      setIsLoading(true);
      
      // Try to load from /data/analysis.json (user's data)
      const response = await fetch('/data/analysis.json');
      if (response.ok) {
        const rawData = await response.json();
        // Adapt the data to match GUI expectations
        const adaptedData = adaptAnalysisData(rawData);
        const finalData = ensureSummary(adaptedData);
        setAnalysisData(finalData);
        return;
      }
    } catch (error) {
      // Silently fail - user can load data via file picker
      console.log('No pre-loaded data found. Use file picker to load analysis.');
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading && !analysisData) {
    return (
      <LoadingSpinner 
        fullScreen 
        message="Loading Security Analysis Platform..." 
        size={60}
      />
    );
  }

  return (
    <Router>
      <div className="cyber-grid" style={{ 
        minHeight: '100vh',
        background: 'var(--bg-primary)',
      }}>
        {analysisData && <TopNav />}
        
        <main style={{ 
          padding: analysisData ? '2rem' : '0',
          maxWidth: '1920px',
          margin: '0 auto',
        }}>
          {!analysisData ? (
            <WelcomeScreen />
          ) : (
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/file-tree" element={<FileTree />} />
              <Route path="/findings" element={<AllFindings />} />
              <Route path="/dangerous-functions" element={<DangerousFunctions />} />
              <Route path="/secrets" element={<Secrets />} />
              <Route path="/taint-sources" element={<TaintSources />} />
              <Route path="/taint-flows" element={<TaintFlows />} />
              <Route path="/validation" element={<Validation />} />
              <Route path="/crypto" element={<Cryptography />} />
              <Route path="/auth" element={<Authentication />} />
              <Route path="/framework" element={<FrameworkSecurity />} />
              <Route path="/quality" element={<CodeQuality />} />
              <Route path="/antipatterns" element={<AntiPatterns />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/about" element={<About />} />
            </Routes>
          )}
        </main>
      </div>
    </Router>
  );
}

export default App;

