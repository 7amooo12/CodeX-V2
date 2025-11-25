import React, { useState, useEffect } from 'react';
import { theme } from '../../styles/theme';
import { Card } from './Card';
import { Button } from './Button';
import { LoadingSpinner } from './LoadingSpinner';
import { browseDirectory, getHomeDirectory, type BrowseResult, type BrowseItem } from '../../utils/api';

interface FileBrowserProps {
  onSelectPath: (path: string) => void;
  onClose: () => void;
}

export const FileBrowser: React.FC<FileBrowserProps> = ({ onSelectPath, onClose }) => {
  const [currentPath, setCurrentPath] = useState<string>('');
  const [items, setItems] = useState<BrowseItem[]>([]);
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string>('');
  const [highlightedIndex, setHighlightedIndex] = useState<number>(-1);
  const [showDriveDropdown, setShowDriveDropdown] = useState(false);
  const [availableDrives, setAvailableDrives] = useState<BrowseItem[]>([]);

  // Load initial directory
  useEffect(() => {
    loadHomeDirectory();
  }, []);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (items.length === 0 || isLoading) return;

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setHighlightedIndex((prev) => Math.min(prev + 1, items.length - 1));
          break;
        case 'ArrowUp':
          e.preventDefault();
          setHighlightedIndex((prev) => Math.max(prev - 1, 0));
          break;
        case 'Enter':
          e.preventDefault();
          if (highlightedIndex >= 0 && highlightedIndex < items.length) {
            const item = items[highlightedIndex];
            if (item.is_dir) {
              loadDirectory(item.path);
            }
          }
          break;
        case 'Backspace':
          e.preventDefault();
          if (parentPath !== null) {
            handleGoUp();
          }
          break;
        case 'Escape':
          e.preventDefault();
          onClose();
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [items, highlightedIndex, parentPath, isLoading]);

  // Reset highlighted index when items change
  useEffect(() => {
    setHighlightedIndex(items.length > 0 ? 0 : -1);
  }, [items.length]);

  const loadHomeDirectory = async () => {
    try {
      setIsLoading(true);
      const { home_directory } = await getHomeDirectory();
      await loadDirectory(home_directory);
    } catch (err: any) {
      // If home fails, load root
      await loadDirectory('');
    }
  };

  const loadDirectory = async (path: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result: BrowseResult = await browseDirectory(path);
      
      setCurrentPath(result.current_path);
      setItems(result.items);
      setParentPath(result.parent_path);
      setSelectedPath(result.current_path);
      
      // If we're at drive selection, save the drives list
      if (!path && result.items.length > 0 && result.items[0].type === 'drive') {
        setAvailableDrives(result.items);
      }
      
    } catch (err: any) {
      setError(err.message || 'Failed to load directory');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePathClick = async () => {
    // Load drives if not already loaded
    if (availableDrives.length === 0) {
      try {
        const result: BrowseResult = await browseDirectory('');
        setAvailableDrives(result.items.filter(item => item.type === 'drive'));
      } catch (err) {
        console.error('Failed to load drives:', err);
      }
    }
    setShowDriveDropdown(!showDriveDropdown);
  };

  const handleDriveSelect = (drive: BrowseItem) => {
    loadDirectory(drive.path);
    setShowDriveDropdown(false);
  };

  const handleItemClick = (item: BrowseItem) => {
    if (item.is_dir) {
      loadDirectory(item.path);
    }
  };

  const handleItemDoubleClick = (item: BrowseItem) => {
    if (item.is_dir) {
      setSelectedPath(item.path);
    }
  };

  const handleGoUp = () => {
    // If we're at a drive root (like C:\), go back to drive selection
    if (currentPath && /^[A-Z]:\\?$/i.test(currentPath)) {
      loadDirectory(''); // Load drive selection
    } else if (parentPath !== null) {
      loadDirectory(parentPath);
    }
  };

  const handleShowDrives = () => {
    loadDirectory(''); // Empty path shows drives on Windows
  };

  const handleSelectCurrent = () => {
    if (selectedPath || currentPath) {
      onSelectPath(selectedPath || currentPath);
      onClose();
    }
  };

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (timestamp: number): string => {
    if (!timestamp) return '';
    return new Date(timestamp * 1000).toLocaleDateString();
  };

  const getIcon = (item: BrowseItem): string => {
    if (item.type === 'drive') return '💾';
    if (item.type === 'directory') return '📁';
    return '📄';
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: theme.colors.background.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: theme.zIndex.modal,
        padding: theme.spacing.lg,
      }}
      onClick={onClose}
    >
      <Card
        glow
        padding="lg"
        style={{
          maxWidth: '900px',
          width: '100%',
          maxHeight: '80vh',
          display: 'flex',
          flexDirection: 'column',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: theme.spacing.md,
            paddingBottom: theme.spacing.md,
            borderBottom: `1px solid ${theme.colors.border.primary}`,
          }}
        >
          <h3
            style={{
              fontSize: theme.typography.fontSize.xl,
              fontWeight: theme.typography.fontWeight.semibold,
              color: theme.colors.accent.cyan,
              margin: 0,
            }}
          >
            📂 Browse Local Files
          </h3>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: theme.colors.text.secondary,
              fontSize: theme.typography.fontSize['2xl'],
              cursor: 'pointer',
              padding: theme.spacing.xs,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        {/* Navigation Bar */}
        <div
          style={{
            display: 'flex',
            gap: theme.spacing.sm,
            marginBottom: theme.spacing.md,
            alignItems: 'center',
          }}
        >
          <Button
            variant="secondary"
            size="sm"
            icon="⬆️"
            onClick={handleGoUp}
            disabled={isLoading || (!parentPath && !currentPath.match(/^[A-Z]:\\?$/i))}
          >
            Up
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="💾"
            onClick={handleShowDrives}
            disabled={isLoading}
            title="Show all drives (C:, D:, etc.)"
          >
            Drives
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="🏠"
            onClick={loadHomeDirectory}
            disabled={isLoading}
          >
            Home
          </Button>
          <div
            style={{
              flex: 1,
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              border: `1px solid ${theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.sm,
              fontSize: theme.typography.fontSize.sm,
              fontFamily: theme.typography.fontFamily.mono,
              color: currentPath ? theme.colors.text.primary : theme.colors.text.tertiary,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing.sm,
            }}
            title={currentPath || 'Drive Selection'}
          >
            {currentPath ? (
              <>
                <span style={{ color: theme.colors.accent.cyan }}>📍</span>
                {currentPath}
              </>
            ) : (
              <>
                <span style={{ color: theme.colors.accent.green }}>💾</span>
                Drive Selection - Choose your drive
              </>
            )}
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div
            style={{
              marginBottom: theme.spacing.md,
              padding: theme.spacing.sm,
              background: `${theme.colors.severity.critical}20`,
              border: `1px solid ${theme.colors.severity.critical}`,
              borderRadius: theme.borderRadius.sm,
              color: theme.colors.severity.critical,
              fontSize: theme.typography.fontSize.sm,
            }}
          >
            ⚠️ {error}
          </div>
        )}

        {/* File List */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            background: theme.colors.background.secondary,
            border: `2px solid ${theme.colors.border.primary}`,
            borderRadius: theme.borderRadius.md,
            marginBottom: theme.spacing.md,
            minHeight: '400px',
            maxHeight: '500px',
            overflow: 'hidden',
          }}
        >
          {/* Header Row with Borders */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing.md,
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              borderBottom: `2px solid ${theme.colors.border.primary}`,
              fontWeight: theme.typography.fontWeight.semibold,
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.text.secondary,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            <div style={{ fontSize: '1.5rem', minWidth: '30px' }}>📋</div>
            <div style={{ flex: 1 }}>Name</div>
            <div style={{ minWidth: '80px', textAlign: 'right' }}>Size</div>
            <div style={{ minWidth: '100px', textAlign: 'right' }}>Modified</div>
          </div>

          {/* Scrollable Content Area */}
          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              overflowX: 'hidden',
            }}
            className="custom-scrollbar"
          >
            {isLoading ? (
              <div style={{ padding: theme.spacing.xl, textAlign: 'center' }}>
                <LoadingSpinner message="Loading directory..." size={40} />
              </div>
            ) : items.length === 0 ? (
              <div
                style={{
                  padding: theme.spacing.xl,
                  textAlign: 'center',
                  color: theme.colors.text.tertiary,
                }}
              >
                {currentPath ? '📭 Empty directory' : '💾 Select a drive to start browsing'}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {items.map((item, index) => {
                  const isHighlighted = highlightedIndex === index;
                  const isSelected = selectedPath === item.path;
                  
                  return (
                    <div
                      key={`${item.path}-${index}`}
                      onClick={() => {
                        handleItemClick(item);
                        setHighlightedIndex(index);
                      }}
                      onDoubleClick={() => handleItemDoubleClick(item)}
                      onMouseEnter={() => setHighlightedIndex(index)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: theme.spacing.md,
                        padding: `${theme.spacing.sm} ${theme.spacing.md}`,
                        borderBottom: `1px solid ${theme.colors.border.tertiary}`,
                        borderLeft: isHighlighted ? `3px solid ${theme.colors.accent.cyan}` : 'none',
                        paddingLeft: isHighlighted ? `calc(${theme.spacing.md} - 3px)` : theme.spacing.md,
                        cursor: item.is_dir ? 'pointer' : 'default',
                        transition: theme.transitions.fast,
                        background: isSelected
                          ? `linear-gradient(90deg, ${theme.colors.accent.cyan}30, ${theme.colors.accent.cyan}10)`
                          : isHighlighted
                          ? `${theme.colors.accent.cyan}15`
                          : 'transparent',
                      }}
                    >
                    {/* Icon */}
                    <div style={{ fontSize: '1.5rem', minWidth: '30px' }}>{getIcon(item)}</div>

                    {/* Name */}
                    <div
                      style={{
                        flex: 1,
                        fontSize: theme.typography.fontSize.sm,
                        color: item.is_dir ? theme.colors.accent.cyan : theme.colors.text.primary,
                        fontWeight: item.is_dir
                          ? theme.typography.fontWeight.semibold
                          : theme.typography.fontWeight.normal,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={item.name}
                    >
                      {item.name}
                    </div>

                    {/* Size */}
                    {!item.is_dir && item.size !== undefined ? (
                      <div
                        style={{
                          fontSize: theme.typography.fontSize.xs,
                          color: theme.colors.text.tertiary,
                          minWidth: '80px',
                          textAlign: 'right',
                          fontFamily: theme.typography.fontFamily.mono,
                        }}
                      >
                        {formatSize(item.size)}
                      </div>
                    ) : (
                      <div style={{ minWidth: '80px' }}></div>
                    )}

                    {/* Modified Date */}
                    {item.modified ? (
                      <div
                        style={{
                          fontSize: theme.typography.fontSize.xs,
                          color: theme.colors.text.tertiary,
                          minWidth: '100px',
                          textAlign: 'right',
                          fontFamily: theme.typography.fontFamily.mono,
                        }}
                      >
                        {formatDate(item.modified)}
                      </div>
                    ) : (
                      <div style={{ minWidth: '100px' }}></div>
                    )}
                  </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Footer with Item Count - Border at Bottom */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              borderTop: `2px solid ${theme.colors.border.primary}`,
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.text.tertiary,
            }}
          >
            <div>
              {items.length} item{items.length !== 1 ? 's' : ''}
              {items.filter(i => i.is_dir).length > 0 && 
                ` (${items.filter(i => i.is_dir).length} folder${items.filter(i => i.is_dir).length !== 1 ? 's' : ''})`
              }
            </div>
            <div style={{ color: theme.colors.accent.cyan, fontFamily: theme.typography.fontFamily.mono }}>
              {selectedPath ? '✓ Selected' : 'Select a folder'}
            </div>
          </div>
        </div>

        {/* Selected Path Display - Clickable with Drive Dropdown */}
        <div
          style={{
            marginBottom: theme.spacing.md,
            position: 'relative',
          }}
        >
          <div
            onClick={handlePathClick}
            style={{
              padding: theme.spacing.sm,
              background: theme.colors.background.tertiary,
              border: `2px solid ${showDriveDropdown ? theme.colors.accent.cyan : theme.colors.border.primary}`,
              borderRadius: theme.borderRadius.sm,
              cursor: 'pointer',
              transition: theme.transitions.fast,
              boxShadow: showDriveDropdown ? theme.shadows.glow.cyan : 'none',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = theme.colors.accent.cyan;
            }}
            onMouseLeave={(e) => {
              if (!showDriveDropdown) {
                e.currentTarget.style.borderColor = theme.colors.border.primary;
              }
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: theme.typography.fontSize.xs,
                    color: theme.colors.text.tertiary,
                    marginBottom: theme.spacing.xs,
                  }}
                >
                  Selected Path: {selectedPath ? '(Click to change drive)' : '(Click to select drive)'}
                </div>
                <div
                  style={{
                    fontSize: theme.typography.fontSize.sm,
                    fontFamily: theme.typography.fontFamily.mono,
                    color: theme.colors.accent.green,
                    wordBreak: 'break-all',
                  }}
                >
                  {selectedPath || currentPath || 'No path selected'}
                </div>
              </div>
              <div
                style={{
                  fontSize: theme.typography.fontSize.xl,
                  color: theme.colors.accent.cyan,
                  transform: showDriveDropdown ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: theme.transitions.fast,
                }}
              >
                💾
              </div>
            </div>
          </div>

          {/* Drive Dropdown */}
          {showDriveDropdown && availableDrives.length > 0 && (
            <div
              style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                right: 0,
                marginTop: theme.spacing.xs,
                background: theme.colors.background.secondary,
                border: `2px solid ${theme.colors.accent.cyan}`,
                borderRadius: theme.borderRadius.md,
                boxShadow: theme.shadows.glow.cyan,
                zIndex: 1000,
                maxHeight: '200px',
                overflowY: 'auto',
              }}
              className="custom-scrollbar"
            >
              <div
                style={{
                  padding: theme.spacing.sm,
                  borderBottom: `1px solid ${theme.colors.border.primary}`,
                  fontSize: theme.typography.fontSize.xs,
                  color: theme.colors.text.tertiary,
                  textTransform: 'uppercase',
                  fontWeight: theme.typography.fontWeight.semibold,
                }}
              >
                💾 Select Drive
              </div>
              {availableDrives.map((drive, index) => (
                <div
                  key={drive.path}
                  onClick={() => handleDriveSelect(drive)}
                  style={{
                    padding: theme.spacing.md,
                    borderBottom: index < availableDrives.length - 1 ? `1px solid ${theme.colors.border.tertiary}` : 'none',
                    cursor: 'pointer',
                    transition: theme.transitions.fast,
                    display: 'flex',
                    alignItems: 'center',
                    gap: theme.spacing.md,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = `${theme.colors.accent.cyan}20`;
                    e.currentTarget.style.borderLeft = `3px solid ${theme.colors.accent.cyan}`;
                    e.currentTarget.style.paddingLeft = `calc(${theme.spacing.md} - 3px)`;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.borderLeft = 'none';
                    e.currentTarget.style.paddingLeft = theme.spacing.md;
                  }}
                >
                  <div style={{ fontSize: '2rem' }}>💾</div>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        fontSize: theme.typography.fontSize.base,
                        fontWeight: theme.typography.fontWeight.semibold,
                        color: theme.colors.accent.cyan,
                        fontFamily: theme.typography.fontFamily.mono,
                      }}
                    >
                      {drive.name}
                    </div>
                    <div
                      style={{
                        fontSize: theme.typography.fontSize.xs,
                        color: theme.colors.text.tertiary,
                        marginTop: theme.spacing.xs,
                      }}
                    >
                      {drive.path === currentPath.split('\\')[0] + '\\' ? '✓ Current drive' : 'Click to switch'}
                    </div>
                  </div>
                  {drive.path === currentPath.split('\\')[0] + '\\' && (
                    <div
                      style={{
                        padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                        background: `${theme.colors.accent.green}20`,
                        border: `1px solid ${theme.colors.accent.green}`,
                        borderRadius: theme.borderRadius.sm,
                        fontSize: theme.typography.fontSize.xs,
                        color: theme.colors.accent.green,
                        fontWeight: theme.typography.fontWeight.semibold,
                      }}
                    >
                      ACTIVE
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div style={{ display: 'flex', gap: theme.spacing.md, justifyContent: 'flex-end' }}>
          <Button variant="secondary" size="md" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="md"
            icon="✅"
            onClick={handleSelectCurrent}
            disabled={!selectedPath && !currentPath}
          >
            Select This Folder
          </Button>
        </div>

        {/* Help Text with Keyboard Shortcuts */}
        <div
          style={{
            marginTop: theme.spacing.md,
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: theme.spacing.sm,
          }}
        >
          <div
            style={{
              padding: theme.spacing.sm,
              background: `${theme.colors.accent.blue}10`,
              border: `1px solid ${theme.colors.accent.blue}30`,
              borderRadius: theme.borderRadius.sm,
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.text.tertiary,
            }}
          >
            <div style={{ fontWeight: 'bold', marginBottom: theme.spacing.xs, color: theme.colors.accent.cyan }}>
              🖱️ Mouse Controls
            </div>
            <div>• <strong>Click Selected Path</strong>: Quick drive dropdown ⭐</div>
            <div>• <strong>Single-click folder</strong>: Open folder</div>
            <div>• <strong>Double-click folder</strong>: Select folder</div>
            <div>• <strong>Drives button</strong>: Show all drives</div>
          </div>
          
          <div
            style={{
              padding: theme.spacing.sm,
              background: `${theme.colors.accent.green}10`,
              border: `1px solid ${theme.colors.accent.green}30`,
              borderRadius: theme.borderRadius.sm,
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.text.tertiary,
            }}
          >
            <div style={{ fontWeight: 'bold', marginBottom: theme.spacing.xs, color: theme.colors.accent.green }}>
              ⌨️ Keyboard Shortcuts
            </div>
            <div>• <strong>↑/↓</strong>: Navigate items</div>
            <div>• <strong>Enter</strong>: Open folder/drive</div>
            <div>• <strong>Backspace</strong>: Go up / Show drives</div>
            <div>• <strong>Esc</strong>: Close browser</div>
          </div>
        </div>
      </Card>
    </div>
  );
};

