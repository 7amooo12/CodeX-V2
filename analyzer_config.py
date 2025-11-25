"""
Production Configuration for Comprehensive Analyzer
===================================================
Configuration options for production deployment
"""

class AnalyzerConfig:
    """Production configuration settings"""
    
    # Performance Settings
    MAX_WORKERS = 4  # Number of threads for parallel processing
    MAX_FILE_SIZE_MB = 10  # Maximum file size to analyze (MB)
    MAX_FILES = None  # Maximum files to analyze (None = unlimited)
    CACHE_SIZE_MB = 100  # File cache size (MB)
    
    # Timeout Settings
    FILE_TIMEOUT_SECONDS = 30  # Timeout for analyzing single file
    TOTAL_TIMEOUT_MINUTES = 60  # Total analysis timeout
    
    # Memory Limits
    MAX_MEMORY_MB = 2048  # Maximum memory usage (MB)
    MEMORY_CHECK_INTERVAL = 10  # Check memory every N files
    
    # Checkpoint Settings
    ENABLE_CHECKPOINTING = True  # Enable checkpoint/resume
    CHECKPOINT_INTERVAL = 100  # Save checkpoint every N files
    CHECKPOINT_DIR = "checkpoints"  # Directory for checkpoint files
    
    # Accuracy Settings
    FALSE_POSITIVE_REDUCTION = True  # Enable false positive filtering
    SKIP_TEST_FILES = False  # Skip test/spec files entirely
    SKIP_VENDOR_CODE = True  # Skip vendor/third-party code
    MIN_ENTROPY_THRESHOLD = 5.5  # Minimum entropy for high-entropy strings
    
    # Output Settings
    ENABLE_PROGRESS_BAR = True  # Show progress bars
    VERBOSE_LOGGING = False  # Enable verbose logging
    SAVE_INTERMEDIATE_RESULTS = False  # Save results during analysis
    
    # Exclusions
    EXCLUDED_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', 
        'venv', 'env', '.venv', '.env', 'virtualenv',
        'build', 'dist', 'output', 'target', 'out',
        '.idea', '.vscode', '.vs', '.settings',
        'vendor', 'vendors', 'third_party', 'external',
        'coverage', '.coverage', '.pytest_cache', '.tox',
        'lib', 'libs', '.gradle', '.mvn',
        'tmp', 'temp', 'cache', '.cache',
        'logs', 'log',
        'bower_components', 'jspm_packages',
        '.next', '.nuxt', '.output',
        'public', 'static', 'assets',
        'migrations',
    }
    
    EXCLUDED_EXTENSIONS = {
        '.min.js', '.min.css', '.map',
        '.lock', '.sum',
        '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.exe', '.dll', '.so', '.dylib',
        '.ttf', '.woff', '.woff2', '.eot',
        '.mp3', '.mp4', '.avi', '.mov',
    }
    
    @classmethod
    def load_from_file(cls, config_file: str):
        """Load configuration from JSON file"""
        import json
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(cls, key.upper()):
                        setattr(cls, key.upper(), value)
        except FileNotFoundError:
            pass  # Use defaults
    
    @classmethod
    def to_dict(cls) -> dict:
        """Export configuration as dictionary"""
        return {
            key: value for key, value in vars(cls).items()
            if not key.startswith('_') and not callable(value)
        }


# Production presets
class ProductionConfig(AnalyzerConfig):
    """Optimized for production - fast and accurate"""
    MAX_WORKERS = 8
    MAX_FILE_SIZE_MB = 5
    ENABLE_CHECKPOINTING = True
    FALSE_POSITIVE_REDUCTION = True
    SKIP_VENDOR_CODE = True


class DevelopmentConfig(AnalyzerConfig):
    """Optimized for development - thorough but slower"""
    MAX_WORKERS = 2
    MAX_FILE_SIZE_MB = 20
    VERBOSE_LOGGING = True
    FALSE_POSITIVE_REDUCTION = False


class FastScanConfig(AnalyzerConfig):
    """Quick scan - speed over thoroughness"""
    MAX_WORKERS = 16
    MAX_FILE_SIZE_MB = 2
    ENABLE_CHECKPOINTING = False
    SKIP_TEST_FILES = True
    SKIP_VENDOR_CODE = True



