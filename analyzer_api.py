#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask API Server for Comprehensive Analyzer
============================================
Provides REST API endpoints for running analyses from the web GUI
"""

import os
import sys
import json
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from typing import Dict, Any, Optional
import uuid

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from comprehensive_analyzer import ComprehensiveAnalyzer

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Store active analyses
active_analyses: Dict[str, Dict[str, Any]] = {}
analysis_lock = threading.Lock()


class AnalysisProgress:
    """Track analysis progress"""
    
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id
        self.status = "initializing"  # initializing, running, completed, error
        self.progress = 0  # 0-100
        self.current_step = ""
        self.steps_completed = 0
        self.total_steps = 8
        self.results = None
        self.error = None
        self.logs = []
        self.start_time = datetime.now().isoformat()
        self.end_time = None
    
    def log(self, message: str, level: str = "info"):
        """Add log message"""
        self.logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def update(self, status: str = None, progress: int = None, step: str = None):
        """Update progress"""
        if status:
            self.status = status
        if progress is not None:
            self.progress = progress
        if step:
            self.current_step = step
            self.steps_completed += 1
            self.log(f"Starting: {step}")
    
    def complete(self, results: Dict[str, Any]):
        """Mark as completed"""
        self.status = "completed"
        self.progress = 100
        self.results = results
        self.end_time = datetime.now().isoformat()
        self.log("Analysis completed successfully", "success")
    
    def fail(self, error: str):
        """Mark as failed"""
        self.status = "error"
        self.error = error
        self.end_time = datetime.now().isoformat()
        self.log(f"Analysis failed: {error}", "error")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "analysis_id": self.analysis_id,
            "status": self.status,
            "progress": self.progress,
            "current_step": self.current_step,
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "logs": self.logs[-20:],  # Last 20 logs
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "has_results": self.results is not None
        }


def run_analysis_background(analysis_id: str, config: Dict[str, Any]):
    """Run analysis in background thread"""
    
    with analysis_lock:
        progress = active_analyses[analysis_id]
    
    try:
        project_path = config['project_path']
        max_workers = config.get('max_workers', 4)
        max_files = config.get('max_files')
        output_format = config.get('output_format', 'json')
        
        progress.update(status="running", progress=10, step="Initializing analyzer")
        
        # Create analyzer (Note: max_workers and max_files are not used by ComprehensiveAnalyzer)
        analyzer = ComprehensiveAnalyzer(project_path=project_path)
        
        progress.update(progress=20, step="Scanning project structure")
        
        # Run analysis
        progress.update(progress=30, step="Analyzing security issues")
        results = analyzer.analyze_all()
        
        progress.update(progress=80, step="Generating reports")
        
        # Save outputs
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        os.makedirs(output_dir, exist_ok=True)
        
        # Always save JSON
        json_path = os.path.join(output_dir, f"analysis_{analysis_id}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        progress.log(f"JSON saved: {json_path}", "success")
        
        # Save PDF if requested
        pdf_path = None
        if output_format in ['pdf', 'both']:
            pdf_path = os.path.join(output_dir, f"analysis_{analysis_id}.pdf")
            try:
                analyzer.generate_pdf(pdf_path)
                progress.log(f"PDF saved: {pdf_path}", "success")
            except Exception as e:
                progress.log(f"PDF generation warning: {str(e)}", "warning")
        
        progress.update(progress=100, step="Complete")
        
        # Store results
        results['_output_files'] = {
            'json': json_path,
            'pdf': pdf_path
        }
        
        progress.complete(results)
        
    except Exception as e:
        progress.fail(str(e))


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "2.1-OPTIMIZED",
        "active_analyses": len(active_analyses)
    })


@app.route('/api/validate-path', methods=['POST'])
def validate_path():
    """Validate project path"""
    data = request.json
    path = data.get('path', '')
    
    if not path:
        return jsonify({"valid": False, "error": "Path is required"}), 400
    
    if not os.path.exists(path):
        return jsonify({"valid": False, "error": "Path does not exist"}), 400
    
    if not os.path.isdir(path):
        return jsonify({"valid": False, "error": "Path is not a directory"}), 400
    
    # Count files
    file_count = 0
    try:
        for root, dirs, files in os.walk(path):
            file_count += len(files)
            if file_count > 10000:  # Stop counting after 10k
                break
    except Exception as e:
        return jsonify({"valid": False, "error": f"Cannot read directory: {str(e)}"}), 400
    
    return jsonify({
        "valid": True,
        "path": os.path.abspath(path),
        "estimated_files": file_count if file_count <= 10000 else "10000+"
    })


@app.route('/api/start-analysis', methods=['POST'])
def start_analysis():
    """Start new analysis"""
    data = request.json
    
    # Validate input
    project_path = data.get('project_path')
    if not project_path or not os.path.exists(project_path):
        return jsonify({"error": "Invalid project path"}), 400
    
    # Create analysis ID
    analysis_id = str(uuid.uuid4())[:8]
    
    # Create progress tracker
    progress = AnalysisProgress(analysis_id)
    progress.log(f"Analysis started for: {project_path}")
    
    # Store in active analyses
    with analysis_lock:
        active_analyses[analysis_id] = progress
    
    # Start analysis in background
    config = {
        'project_path': project_path,
        'max_workers': data.get('max_workers', 4),
        'max_files': data.get('max_files'),
        'output_format': data.get('output_format', 'json')
    }
    
    thread = threading.Thread(
        target=run_analysis_background,
        args=(analysis_id, config),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        "analysis_id": analysis_id,
        "status": "started",
        "message": "Analysis started successfully"
    })


@app.route('/api/analysis/<analysis_id>/status', methods=['GET'])
def get_analysis_status(analysis_id: str):
    """Get analysis status"""
    with analysis_lock:
        progress = active_analyses.get(analysis_id)
    
    if not progress:
        return jsonify({"error": "Analysis not found"}), 404
    
    return jsonify(progress.to_dict())


@app.route('/api/analysis/<analysis_id>/results', methods=['GET'])
def get_analysis_results(analysis_id: str):
    """Get analysis results"""
    with analysis_lock:
        progress = active_analyses.get(analysis_id)
    
    if not progress:
        return jsonify({"error": "Analysis not found"}), 404
    
    if progress.status != "completed":
        return jsonify({"error": "Analysis not completed yet"}), 400
    
    if not progress.results:
        return jsonify({"error": "No results available"}), 404
    
    return jsonify(progress.results)


@app.route('/api/analysis/<analysis_id>/download/<file_type>', methods=['GET'])
def download_analysis_file(analysis_id: str, file_type: str):
    """Download analysis file (json or pdf)"""
    with analysis_lock:
        progress = active_analyses.get(analysis_id)
    
    if not progress or not progress.results:
        return jsonify({"error": "Analysis not found or not completed"}), 404
    
    output_files = progress.results.get('_output_files', {})
    file_path = output_files.get(file_type)
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": f"{file_type.upper()} file not available"}), 404
    
    return send_file(file_path, as_attachment=True)


@app.route('/api/analyses', methods=['GET'])
def list_analyses():
    """List all analyses"""
    with analysis_lock:
        analyses = [
            {
                "analysis_id": aid,
                "status": progress.status,
                "progress": progress.progress,
                "start_time": progress.start_time
            }
            for aid, progress in active_analyses.items()
        ]
    
    return jsonify({"analyses": analyses})


@app.route('/api/system-info', methods=['GET'])
def get_system_info():
    """Get system information"""
    import platform
    import multiprocessing
    
    return jsonify({
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "cpu_count": multiprocessing.cpu_count(),
        "recommended_threads": min(multiprocessing.cpu_count(), 8)
    })


@app.route('/api/browse', methods=['POST'])
def browse_directory():
    """Browse local file system"""
    data = request.json
    path = data.get('path', '')
    
    # If no path provided, return root drives (Windows) or home directory
    if not path:
        import platform
        if platform.system() == 'Windows':
            # List available drives
            import string
            drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append({
                        'name': drive,
                        'path': drive,
                        'type': 'drive',
                        'is_dir': True
                    })
            return jsonify({
                'current_path': '',
                'parent_path': None,
                'items': drives
            })
        else:
            # Unix-like: start from home or root
            path = os.path.expanduser('~')
    
    # Normalize path
    path = os.path.abspath(path)
    
    # Security check - prevent access to sensitive directories
    # (You can customize this list based on your needs)
    forbidden_paths = []
    if any(path.startswith(forbidden) for forbidden in forbidden_paths):
        return jsonify({"error": "Access denied to this directory"}), 403
    
    if not os.path.exists(path):
        return jsonify({"error": "Path does not exist"}), 404
    
    if not os.path.isdir(path):
        return jsonify({"error": "Path is not a directory"}), 400
    
    try:
        items = []
        
        # List directory contents
        for entry_name in os.listdir(path):
            entry_path = os.path.join(path, entry_name)
            
            try:
                is_dir = os.path.isdir(entry_path)
                
                # Get basic info
                item = {
                    'name': entry_name,
                    'path': entry_path,
                    'type': 'directory' if is_dir else 'file',
                    'is_dir': is_dir
                }
                
                # Try to get size (skip if no permission)
                if not is_dir:
                    try:
                        item['size'] = os.path.getsize(entry_path)
                    except (OSError, PermissionError):
                        item['size'] = 0
                
                # Try to get modification time
                try:
                    item['modified'] = os.path.getmtime(entry_path)
                except (OSError, PermissionError):
                    item['modified'] = 0
                
                items.append(item)
                
            except (OSError, PermissionError):
                # Skip files/folders we can't access
                continue
        
        # Sort: directories first, then files, alphabetically
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        # Get parent directory
        parent_path = os.path.dirname(path) if path != os.path.dirname(path) else None
        
        return jsonify({
            'current_path': path,
            'parent_path': parent_path,
            'items': items,
            'total_items': len(items)
        })
        
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": f"Error browsing directory: {str(e)}"}), 500


@app.route('/api/get-home-directory', methods=['GET'])
def get_home_directory():
    """Get user's home directory"""
    home = os.path.expanduser('~')
    return jsonify({
        'home_directory': home,
        'exists': os.path.exists(home)
    })


@app.route('/api/read-file', methods=['POST'])
def read_file_content():
    """Read file content for preview"""
    data = request.json
    file_path = data.get('file_path', '')
    start_line = data.get('start_line', 1)
    end_line = data.get('end_line', None)
    context_lines = data.get('context_lines', 10)  # Lines before/after
    
    if not file_path:
        return jsonify({"error": "File path is required"}), 400
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File does not exist"}), 404
    
    if not os.path.isfile(file_path):
        return jsonify({"error": "Path is not a file"}), 400
    
    try:
        # Read file with encoding detection
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        
        # Calculate context range
        if end_line is None:
            end_line = start_line
        
        context_start = max(1, start_line - context_lines)
        context_end = min(total_lines, end_line + context_lines)
        
        # Get file extension for language detection
        _, ext = os.path.splitext(file_path)
        
        # Language mapping
        language_map = {
            '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript', '.java': 'java',
            '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp', '.go': 'go',
            '.php': 'php', '.rb': 'ruby', '.rs': 'rust', '.swift': 'swift',
            '.kt': 'kotlin', '.scala': 'scala', '.sql': 'sql',
            '.html': 'html', '.css': 'css', '.scss': 'scss',
            '.json': 'json', '.xml': 'xml', '.yaml': 'yaml', '.yml': 'yaml',
            '.sh': 'bash', '.bash': 'bash', '.md': 'markdown'
        }
        
        language = language_map.get(ext.lower(), 'plaintext')
        
        # Prepare line data with metadata
        line_data = []
        for i in range(context_start - 1, context_end):
            if i < len(lines):
                line_num = i + 1
                is_highlighted = start_line <= line_num <= end_line
                line_data.append({
                    'line_number': line_num,
                    'content': lines[i].rstrip('\n\r'),
                    'is_highlighted': is_highlighted,
                    'is_context': not is_highlighted
                })
        
        return jsonify({
            'file_path': file_path,
            'language': language,
            'total_lines': total_lines,
            'lines': line_data,
            'highlight_start': start_line,
            'highlight_end': end_line,
            'context_start': context_start,
            'context_end': context_end
        })
        
    except UnicodeDecodeError:
        return jsonify({"error": "File encoding not supported"}), 400
    except Exception as e:
        return jsonify({"error": f"Error reading file: {str(e)}"}), 500


if __name__ == '__main__':
    print("=" * 80)
    print("🚀 CodeX Analysis Platform - API Server")
    print("=" * 80)
    print(f"\n✅ Server starting on http://localhost:5000")
    print(f"📡 CORS enabled for React frontend")
    print(f"🔧 Analyzer version: 2.1-OPTIMIZED\n")
    print("=" * 80)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )

