// Cyber Security Theme - Design System

export const theme = {
  // Color Palette
  colors: {
    // Background
    background: {
      primary: '#020b14',
      secondary: '#0a1621',
      tertiary: '#0f1e2e',
      overlay: 'rgba(2, 11, 20, 0.95)',
      card: 'rgba(15, 30, 46, 0.6)',
      cardHover: 'rgba(15, 30, 46, 0.8)',
    },
    
    // Accent Colors
    accent: {
      green: '#00ff9a',
      cyan: '#12e2f0',
      blue: '#008cff',
      purple: '#a855f7',
      yellow: '#fbbf24',
    },
    
    // Severity Colors
    severity: {
      critical: '#ff3b3b',
      high: '#ff6b35',
      medium: '#fbbf24',
      low: '#10b981',
      info: '#3b82f6',
    },
    
    // Status Colors
    status: {
      success: '#00ff9a',
      warning: '#fbbf24',
      error: '#ff3b3b',
      info: '#12e2f0',
    },
    
    // Text Colors
    text: {
      primary: '#ffffff',
      secondary: '#a0aec0',
      tertiary: '#718096',
      disabled: '#4a5568',
      accent: '#00ff9a',
    },
    
    // Border Colors
    border: {
      primary: 'rgba(18, 226, 240, 0.2)',
      secondary: 'rgba(0, 255, 154, 0.2)',
      tertiary: 'rgba(255, 255, 255, 0.1)',
      glow: 'rgba(0, 255, 154, 0.5)',
    },
  },
  
  // Typography
  typography: {
    fontFamily: {
      primary: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      mono: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
      display: "'Orbitron', 'Inter', sans-serif",
    },
    fontSize: {
      xs: '0.75rem',    // 12px
      sm: '0.875rem',   // 14px
      base: '1rem',     // 16px
      lg: '1.125rem',   // 18px
      xl: '1.25rem',    // 20px
      '2xl': '1.5rem',  // 24px
      '3xl': '1.875rem',// 30px
      '4xl': '2.25rem', // 36px
      '5xl': '3rem',    // 48px
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
      extrabold: 800,
    },
  },
  
  // Spacing
  spacing: {
    xs: '0.25rem',   // 4px
    sm: '0.5rem',    // 8px
    md: '1rem',      // 16px
    lg: '1.5rem',    // 24px
    xl: '2rem',      // 32px
    '2xl': '3rem',   // 48px
    '3xl': '4rem',   // 64px
  },
  
  // Border Radius
  borderRadius: {
    sm: '0.25rem',
    md: '0.5rem',
    lg: '0.75rem',
    xl: '1rem',
    full: '9999px',
  },
  
  // Shadows & Glows
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.5)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.5)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.5)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
    inner: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.5)',
    glow: {
      green: '0 0 20px rgba(0, 255, 154, 0.5)',
      cyan: '0 0 20px rgba(18, 226, 240, 0.5)',
      blue: '0 0 20px rgba(0, 140, 255, 0.5)',
      red: '0 0 20px rgba(255, 59, 59, 0.5)',
    },
  },
  
  // Transitions
  transitions: {
    fast: '150ms ease-in-out',
    normal: '300ms ease-in-out',
    slow: '500ms ease-in-out',
  },
  
  // Z-Index
  zIndex: {
    dropdown: 1000,
    sticky: 1020,
    fixed: 1030,
    modalBackdrop: 1040,
    modal: 1050,
    popover: 1060,
    tooltip: 1070,
  },
  
  // Breakpoints
  breakpoints: {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },
};

// CSS Variable Generator
export const generateCSSVariables = () => {
  return `
    :root {
      /* Background Colors */
      --bg-primary: ${theme.colors.background.primary};
      --bg-secondary: ${theme.colors.background.secondary};
      --bg-tertiary: ${theme.colors.background.tertiary};
      --bg-overlay: ${theme.colors.background.overlay};
      --bg-card: ${theme.colors.background.card};
      --bg-card-hover: ${theme.colors.background.cardHover};
      
      /* Accent Colors */
      --accent-green: ${theme.colors.accent.green};
      --accent-cyan: ${theme.colors.accent.cyan};
      --accent-blue: ${theme.colors.accent.blue};
      --accent-purple: ${theme.colors.accent.purple};
      --accent-yellow: ${theme.colors.accent.yellow};
      
      /* Severity Colors */
      --severity-critical: ${theme.colors.severity.critical};
      --severity-high: ${theme.colors.severity.high};
      --severity-medium: ${theme.colors.severity.medium};
      --severity-low: ${theme.colors.severity.low};
      --severity-info: ${theme.colors.severity.info};
      
      /* Text Colors */
      --text-primary: ${theme.colors.text.primary};
      --text-secondary: ${theme.colors.text.secondary};
      --text-tertiary: ${theme.colors.text.tertiary};
      --text-disabled: ${theme.colors.text.disabled};
      --text-accent: ${theme.colors.text.accent};
      
      /* Border Colors */
      --border-primary: ${theme.colors.border.primary};
      --border-secondary: ${theme.colors.border.secondary};
      --border-tertiary: ${theme.colors.border.tertiary};
      --border-glow: ${theme.colors.border.glow};
      
      /* Font Families */
      --font-primary: ${theme.typography.fontFamily.primary};
      --font-mono: ${theme.typography.fontFamily.mono};
      --font-display: ${theme.typography.fontFamily.display};
      
      /* Transitions */
      --transition-fast: ${theme.transitions.fast};
      --transition-normal: ${theme.transitions.normal};
      --transition-slow: ${theme.transitions.slow};
    }
  `;
};

export default theme;

