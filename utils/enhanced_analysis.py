"""
Enhanced Security Analysis Features
- File tree hierarchy with risk indicators
- Intelligent findings deduplication
- Advanced data flow visualization
- Professional formatting utilities
"""

import os
from collections import defaultdict
from typing import Dict, List, Any

# Risk indicator icons
RISK_ICONS = {
    'critical': '🔥',
    'high': '⚠️',
    'medium': '🟡',
    'low': '🟢',
    'clean': '✓'
}

def generate_file_tree(root_path: str, security_data: dict = None) -> str:
    """
    Generate a professional file tree hierarchy with risk indicators
    """
    tree_lines = []
    tree_lines.append("FILE TREE HIERARCHY WITH RISK INDICATORS")
    tree_lines.append("=" * 80)
    tree_lines.append("")
    
    # Calculate risk per file
    file_risks = {}
    if security_data:
        for file_path, data in security_data.items():
            risk_score = 0
            risk_score += len(data.get('dangerous_functions', [])) * 10
            risk_score += len([s for s in data.get('secrets', []) if s['type'] in ['aws_key', 'private_key', 'github_token']]) * 15
            risk_score += len(data.get('taint_sources', [])) * 5
            
            if risk_score >= 50:
                file_risks[file_path] = ('critical', RISK_ICONS['critical'])
            elif risk_score >= 20:
                file_risks[file_path] = ('high', RISK_ICONS['high'])
            elif risk_score >= 5:
                file_risks[file_path] = ('medium', RISK_ICONS['medium'])
            elif risk_score > 0:
                file_risks[file_path] = ('low', RISK_ICONS['low'])
            else:
                file_risks[file_path] = ('clean', RISK_ICONS['clean'])
    
    # Build tree structure
    def walk_directory(path, prefix="", is_last=True):
        """Recursively walk directory and build tree"""
        try:
            if os.path.isfile(path):
                # Single file
                risk_level, icon = file_risks.get(path, ('clean', ''))
                filename = os.path.basename(path)
                tree_lines.append(f"{prefix}{'└── ' if is_last else '├── '}{icon} {filename}")
                return
            
            items = []
            try:
                items = sorted(os.listdir(path))
            except PermissionError:
                tree_lines.append(f"{prefix}{'└── ' if is_last else '├── '}[Permission Denied]")
                return
            
            # Filter out common ignored directories
            ignored = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.env', 'dist', 'build'}
            items = [i for i in items if i not in ignored and not i.startswith('.')]
            
            dirs = [i for i in items if os.path.isdir(os.path.join(path, i))]
            files = [i for i in items if os.path.isfile(os.path.join(path, i))]
            
            # Show files
            for i, filename in enumerate(files):
                file_path = os.path.join(path, filename)
                risk_level, icon = file_risks.get(file_path, ('clean', ''))
                is_file_last = (i == len(files) - 1) and len(dirs) == 0
                connector = '└── ' if is_file_last else '├── '
                
                # Add risk indicator
                if risk_level in ['critical', 'high']:
                    tree_lines.append(f"{prefix}{connector}{icon} **{filename}** [{risk_level.upper()}]")
                elif risk_level == 'medium':
                    tree_lines.append(f"{prefix}{connector}{icon} {filename} [{risk_level}]")
                else:
                    tree_lines.append(f"{prefix}{connector}{icon} {filename}")
            
            # Show directories recursively
            for i, dirname in enumerate(dirs):
                dir_path = os.path.join(path, dirname)
                is_dir_last = i == len(dirs) - 1
                connector = '└── ' if is_dir_last else '├── '
                
                tree_lines.append(f"{prefix}{connector}📁 {dirname}/")
                
                extension = '    ' if is_dir_last else '│   '
                walk_directory(dir_path, prefix + extension, True)
        
        except Exception as e:
            tree_lines.append(f"{prefix}[Error: {str(e)}]")
    
    # Start walking
    if os.path.isfile(root_path):
        walk_directory(root_path)
    else:
        tree_lines.append(f"📦 {os.path.basename(os.path.abspath(root_path))}/")
        walk_directory(root_path, "", True)
    
    tree_lines.append("")
    tree_lines.append("Legend:")
    tree_lines.append(f"  {RISK_ICONS['critical']} = CRITICAL - Immediate attention required")
    tree_lines.append(f"  {RISK_ICONS['high']} = HIGH - Review and fix soon")
    tree_lines.append(f"  {RISK_ICONS['medium']} = MEDIUM - Security concern")
    tree_lines.append(f"  {RISK_ICONS['low']} = LOW - Minor issue")
    tree_lines.append(f"  {RISK_ICONS['clean']} = Clean - No issues detected")
    tree_lines.append("")
    
    return "\n".join(tree_lines)


def deduplicate_findings(security_data: dict) -> dict:
    """
    Intelligently deduplicate findings by file with line number aggregation
    """
    deduplicated = {
        'dangerous_functions': {},
        'secrets': {},
        'taint_sources': {},
        'file_network_ops': {}
    }
    
    for file_path, data in security_data.items():
        # Process dangerous functions
        for func in data.get('dangerous_functions', []):
            key = (file_path, func['function'], func['category'])
            if key not in deduplicated['dangerous_functions']:
                deduplicated['dangerous_functions'][key] = {
                    'file': file_path,
                    'function': func['function'],
                    'category': func['category'],
                    'language': func['language'],
                    'lines': [],
                    'contexts': [],
                    'count': 0
                }
            deduplicated['dangerous_functions'][key]['lines'].append(func['line'])
            deduplicated['dangerous_functions'][key]['contexts'].append(func['context'])
            deduplicated['dangerous_functions'][key]['count'] += 1
        
        # Process secrets
        for secret in data.get('secrets', []):
            key = (file_path, secret['type'], secret['value'][:50])
            if key not in deduplicated['secrets']:
                deduplicated['secrets'][key] = {
                    'file': file_path,
                    'type': secret['type'],
                    'value': secret['value'],
                    'lines': [],
                    'count': 0
                }
            if 'line' in secret:
                deduplicated['secrets'][key]['lines'].append(secret['line'])
            deduplicated['secrets'][key]['count'] += 1
        
        # Process taint sources
        for source in data.get('taint_sources', []):
            key = (file_path, source['source'])
            if key not in deduplicated['taint_sources']:
                deduplicated['taint_sources'][key] = {
                    'file': file_path,
                    'source': source['source'],
                    'language': source['language'],
                    'lines': [],
                    'count': 0
                }
            deduplicated['taint_sources'][key]['lines'].append(source['line'])
            deduplicated['taint_sources'][key]['count'] += 1
        
        # Process file/network operations
        for op in data.get('file_network_ops', []):
            key = (file_path, op['operation'], op['pattern'])
            if key not in deduplicated['file_network_ops']:
                deduplicated['file_network_ops'][key] = {
                    'file': file_path,
                    'operation': op['operation'],
                    'pattern': op['pattern'],
                    'language': op['language'],
                    'lines': [],
                    'count': 0
                }
            deduplicated['file_network_ops'][key]['lines'].append(op['line'])
            deduplicated['file_network_ops'][key]['count'] += 1
    
    return deduplicated


def format_line_numbers(lines: List[int]) -> str:
    """
    Format line numbers intelligently:
    - Single: 52
    - Range: 88-104
    - Multiple: 14, 66, 190
    """
    if not lines:
        return "N/A"
    
    lines = sorted(set(lines))
    
    if len(lines) == 1:
        return str(lines[0])
    
    # Try to find ranges
    ranges = []
    start = lines[0]
    prev = lines[0]
    
    for i in range(1, len(lines)):
        if lines[i] == prev + 1:
            prev = lines[i]
        else:
            if start == prev:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{prev}")
            start = lines[i]
            prev = lines[i]
    
    # Add last range
    if start == prev:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{prev}")
    
    return ", ".join(ranges)


def generate_intelligent_findings_table(deduplicated: dict) -> str:
    """
    Generate a clean, professional findings table with deduplication
    """
    lines = []
    lines.append("=" * 80)
    lines.append("INTELLIGENT FINDINGS TABLE (DEDUPLICATED)")
    lines.append("=" * 80)
    lines.append("")
    
    # Dangerous Functions Table
    if deduplicated['dangerous_functions']:
        lines.append("🔴 DANGEROUS FUNCTIONS")
        lines.append("-" * 80)
        lines.append(f"{'File':<30} {'Function':<20} {'Category':<18} {'Lines':<15} {'Count':>5}")
        lines.append("-" * 80)
        
        for key, data in sorted(deduplicated['dangerous_functions'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)[:30]:
            file_short = os.path.basename(data['file'])[:29]
            func_short = data['function'][:19]
            category_short = data['category'][:17]
            line_str = format_line_numbers(data['lines'])[:14]
            count = data['count']
            
            # Determine risk icon
            if data['category'] in ['code_execution', 'command_injection', 'deserialization']:
                icon = RISK_ICONS['critical']
            elif data['category'] in ['sql_injection', 'buffer_overflow']:
                icon = RISK_ICONS['high']
            else:
                icon = RISK_ICONS['medium']
            
            lines.append(f"{icon} {file_short:<28} {func_short:<20} {category_short:<18} {line_str:<15} {count:>5}")
        
        lines.append("")
    
    # Secrets Table
    if deduplicated['secrets']:
        lines.append("🔑 HARDCODED SECRETS")
        lines.append("-" * 80)
        lines.append(f"{'File':<30} {'Type':<20} {'Lines':<15} {'Count':>5}")
        lines.append("-" * 80)
        
        for key, data in sorted(deduplicated['secrets'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)[:20]:
            file_short = os.path.basename(data['file'])[:29]
            type_short = data['type'][:19]
            line_str = format_line_numbers(data['lines'])[:14]
            count = data['count']
            
            # Determine risk
            if data['type'] in ['aws_key', 'private_key', 'github_token']:
                icon = RISK_ICONS['critical']
            else:
                icon = RISK_ICONS['high']
            
            lines.append(f"{icon} {file_short:<28} {type_short:<20} {line_str:<15} {count:>5}")
        
        lines.append("")
    
    # Taint Sources Table
    if deduplicated['taint_sources']:
        lines.append("🚰 USER INPUT SOURCES (TAINT ORIGINS)")
        lines.append("-" * 80)
        lines.append(f"{'File':<30} {'Source':<25} {'Lines':<15} {'Count':>5}")
        lines.append("-" * 80)
        
        for key, data in sorted(deduplicated['taint_sources'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)[:20]:
            file_short = os.path.basename(data['file'])[:29]
            source_short = data['source'][:24]
            line_str = format_line_numbers(data['lines'])[:14]
            count = data['count']
            
            lines.append(f"{RISK_ICONS['high']} {file_short:<28} {source_short:<25} {line_str:<15} {count:>5}")
        
        lines.append("")
    
    # File/Network Operations
    if deduplicated['file_network_ops']:
        lines.append("📂 FILE & NETWORK OPERATIONS")
        lines.append("-" * 80)
        lines.append(f"{'File':<30} {'Operation':<20} {'Lines':<15} {'Count':>5}")
        lines.append("-" * 80)
        
        for key, data in sorted(deduplicated['file_network_ops'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)[:20]:
            file_short = os.path.basename(data['file'])[:29]
            op_short = data['operation'][:19]
            line_str = format_line_numbers(data['lines'])[:14]
            count = data['count']
            
            if data['operation'] in ['file_delete', 'download']:
                icon = RISK_ICONS['high']
            else:
                icon = RISK_ICONS['medium']
            
            lines.append(f"{icon} {file_short:<28} {op_short:<20} {line_str:<15} {count:>5}")
        
        lines.append("")
    
    lines.append("=" * 80)
    lines.append("")
    
    return "\n".join(lines)


def generate_data_flow_diagram(taint_flows: List[dict]) -> str:
    """
    Generate human-readable data flow diagrams
    """
    lines = []
    lines.append("=" * 80)
    lines.append("DATA FLOW & TAINT ANALYSIS DIAGRAM")
    lines.append("=" * 80)
    lines.append("")
    
    if not taint_flows:
        lines.append("✓ No direct taint flows detected.")
        return "\n".join(lines)
    
    lines.append(f"Found {len(taint_flows)} taint flows:\n")
    
    # Group by file
    flows_by_file = defaultdict(list)
    for flow in taint_flows:
        flows_by_file[flow['file']].append(flow)
    
    for file_path, flows in flows_by_file.items():
        lines.append(f"📄 {os.path.basename(file_path)}")
        lines.append("─" * 80)
        
        for i, flow in enumerate(flows[:10], 1):  # Limit to 10 per file
            lines.append(f"\n  Flow #{i}:")
            lines.append(f"    {RISK_ICONS['critical']} RISK: {flow['risk']}")
            lines.append(f"    ")
            lines.append(f"    [USER INPUT]")
            lines.append(f"         ↓")
            lines.append(f"    {flow['source']} (line {flow['source_line']})")
            lines.append(f"         ↓")
            lines.append(f"         ↓  [No Sanitization Detected]")
            lines.append(f"         ↓")
            lines.append(f"    {flow['sink']} (line {flow['sink_line']})")
            lines.append(f"         ↓")
            lines.append(f"    [DANGEROUS SINK] ⚠️")
            lines.append(f"    ")
            lines.append(f"    💥 Impact: {flow['description']}")
            lines.append("")
        
        if len(flows) > 10:
            lines.append(f"  ... and {len(flows) - 10} more flows in this file")
        
        lines.append("")
    
    lines.append("=" * 80)
    lines.append("")
    
    return "\n".join(lines)


def generate_exploit_scenarios(deduplicated: dict, taint_flows: List[dict]) -> List[dict]:
    """
    Generate detailed exploit scenarios based on findings
    """
    scenarios = []
    
    # RCE scenarios from dangerous functions
    for key, data in deduplicated['dangerous_functions'].items():
        if data['category'] == 'code_execution':
            scenarios.append({
                'severity': 'CRITICAL',
                'type': 'Remote Code Execution (RCE)',
                'file': data['file'],
                'lines': data['lines'],
                'description': f"The function `{data['function']}` can execute arbitrary code. "
                              f"If user input flows here (check taint analysis), attackers can run "
                              f"system commands, steal data, or install backdoors.",
                'exploit_example': f"# Example exploit\nmalicious_input = '__import__(\"os\").system(\"rm -rf /\")'\n{data['function']}(malicious_input)",
                'fix': f"Replace {data['function']} with safe alternatives. Use allowlists and validation."
            })
        
        elif data['category'] == 'command_injection':
            scenarios.append({
                'severity': 'CRITICAL',
                'type': 'Command Injection',
                'file': data['file'],
                'lines': data['lines'],
                'description': f"The function `{data['function']}` executes system commands. "
                              f"Unsanitized input can lead to full system compromise.",
                'exploit_example': f"# Example exploit\nmalicious_input = 'file.txt; cat /etc/passwd'\n{data['function']}('cat ' + malicious_input)",
                'fix': f"Use subprocess with shell=False, validate inputs, use allowlists."
            })
        
        elif data['category'] == 'deserialization':
            scenarios.append({
                'severity': 'CRITICAL',
                'type': 'Insecure Deserialization',
                'file': data['file'],
                'lines': data['lines'],
                'description': f"The function `{data['function']}` deserializes untrusted data. "
                              f"Malicious payloads can achieve RCE.",
                'exploit_example': f"# Attacker crafts malicious serialized object\n# When deserialized, executes arbitrary code",
                'fix': f"Avoid deserializing untrusted data. Use safe formats like JSON. Implement allowlists."
            })
    
    # Taint flow scenarios
    for flow in taint_flows:
        scenarios.append({
            'severity': flow['risk'],
            'type': 'Taint Flow Vulnerability',
            'file': flow['file'],
            'lines': [flow['source_line'], flow['sink_line']],
            'description': flow['description'],
            'exploit_example': f"# User controls: {flow['source']}\n# Data flows to: {flow['sink']}\n# No validation detected",
            'fix': "Implement input validation, sanitization, and output encoding."
        })
    
    return scenarios[:15]  # Return top 15

