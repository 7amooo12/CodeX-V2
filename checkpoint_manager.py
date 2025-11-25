"""
Checkpoint Manager for Long-Running Analysis
============================================
Enables pause/resume capability for large projects
"""

import os
import json
import pickle
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional


class CheckpointManager:
    """Manages analysis checkpoints for resume capability"""
    
    def __init__(self, project_path: str, checkpoint_dir: str = "checkpoints"):
        self.project_path = project_path
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Generate unique checkpoint ID based on project path
        self.checkpoint_id = hashlib.md5(project_path.encode()).hexdigest()[:12]
        self.checkpoint_file = os.path.join(
            checkpoint_dir, 
            f"checkpoint_{self.checkpoint_id}.pkl"
        )
        self.metadata_file = os.path.join(
            checkpoint_dir,
            f"checkpoint_{self.checkpoint_id}.json"
        )
    
    def save_checkpoint(self, state: Dict[str, Any]):
        """Save current analysis state"""
        try:
            # Save metadata (human-readable)
            metadata = {
                'project_path': self.project_path,
                'checkpoint_time': datetime.now().isoformat(),
                'files_processed': state.get('files_processed', 0),
                'total_files': state.get('total_files', 0),
                'findings_count': {
                    'dangerous_functions': len(state.get('dangerous_functions', [])),
                    'secrets': len(state.get('secrets', [])),
                    'validation_issues': len(state.get('validation_issues', [])),
                }
            }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Save full state (binary)
            with open(self.checkpoint_file, 'wb') as f:
                pickle.dump(state, f)
            
            return True
        except Exception as e:
            print(f"⚠️  Failed to save checkpoint: {e}")
            return False
    
    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load previous checkpoint if exists"""
        if not os.path.exists(self.checkpoint_file):
            return None
        
        try:
            with open(self.checkpoint_file, 'rb') as f:
                state = pickle.load(f)
            
            # Load metadata for display
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                    print(f"\n📂 Found checkpoint from {metadata.get('checkpoint_time')}")
                    print(f"   Progress: {metadata.get('files_processed')}/{metadata.get('total_files')} files")
                    print(f"   Findings: {sum(metadata.get('findings_count', {}).values())}")
            
            return state
        except Exception as e:
            print(f"⚠️  Failed to load checkpoint: {e}")
            return None
    
    def clear_checkpoint(self):
        """Remove checkpoint files"""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
            if os.path.exists(self.metadata_file):
                os.remove(self.metadata_file)
        except Exception:
            pass
    
    def list_checkpoints(self, checkpoint_dir: str = None) -> list:
        """List all available checkpoints"""
        dir_path = checkpoint_dir or self.checkpoint_dir
        if not os.path.exists(dir_path):
            return []
        
        checkpoints = []
        for filename in os.listdir(dir_path):
            if filename.startswith('checkpoint_') and filename.endswith('.json'):
                filepath = os.path.join(dir_path, filename)
                try:
                    with open(filepath, 'r') as f:
                        metadata = json.load(f)
                        checkpoints.append(metadata)
                except Exception:
                    pass
        
        return sorted(checkpoints, key=lambda x: x.get('checkpoint_time', ''), reverse=True)


class MemoryMonitor:
    """Monitor and manage memory usage"""
    
    def __init__(self, max_memory_mb: int = 2048):
        self.max_memory_mb = max_memory_mb
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        
        try:
            import psutil
            self.psutil_available = True
        except ImportError:
            self.psutil_available = False
    
    def get_current_memory_mb(self) -> float:
        """Get current process memory usage in MB"""
        if not self.psutil_available:
            return 0.0
        
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / (1024 * 1024)  # Convert to MB
        except Exception:
            return 0.0
    
    def check_memory_limit(self) -> bool:
        """Check if memory usage exceeds limit"""
        current_mb = self.get_current_memory_mb()
        return current_mb > self.max_memory_mb
    
    def get_memory_stats(self) -> dict:
        """Get detailed memory statistics"""
        if not self.psutil_available:
            return {
                'available': False,
                'message': 'Install psutil for memory monitoring: pip install psutil'
            }
        
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'available': True,
                'rss_mb': memory_info.rss / (1024 * 1024),
                'vms_mb': memory_info.vms / (1024 * 1024),
                'percent': process.memory_percent(),
                'limit_mb': self.max_memory_mb,
                'within_limit': memory_info.rss < self.max_memory_bytes
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }


class TimeoutManager:
    """Manage operation timeouts"""
    
    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds
        self.start_time = None
    
    def start(self):
        """Start the timeout timer"""
        import time
        self.start_time = time.time()
    
    def check_timeout(self) -> bool:
        """Check if timeout has been exceeded"""
        if self.start_time is None:
            return False
        
        import time
        elapsed = time.time() - self.start_time
        return elapsed > self.timeout_seconds
    
    def get_remaining_seconds(self) -> float:
        """Get remaining time before timeout"""
        if self.start_time is None:
            return self.timeout_seconds
        
        import time
        elapsed = time.time() - self.start_time
        return max(0, self.timeout_seconds - elapsed)


if __name__ == "__main__":
    # Test checkpoint manager
    manager = CheckpointManager("test_project")
    
    # Save test checkpoint
    test_state = {
        'files_processed': 50,
        'total_files': 100,
        'dangerous_functions': [{'file': 'test.py', 'function': 'eval'}] * 10,
        'secrets': []
    }
    
    print("Saving checkpoint...")
    manager.save_checkpoint(test_state)
    
    print("\nLoading checkpoint...")
    loaded = manager.load_checkpoint()
    print(f"Loaded: {loaded is not None}")
    
    print("\nListing checkpoints...")
    checkpoints = manager.list_checkpoints()
    for cp in checkpoints:
        print(f"  - {cp['project_path']} at {cp['checkpoint_time']}")



