import os
import ast
import json as _json
from typing import Dict, Any

# --- Supported languages ---
SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".php": "php",
    ".cpp": "cpp",
    ".c": "c",
    ".rb": "ruby",
    ".go": "go",
    ".json": "json",
    ".env": "env",
}

# --- Language detection ---
def detect_language(file_path: str) -> str:
    _, ext = os.path.splitext(file_path)
    return SUPPORTED_LANGUAGES.get(ext.lower(), "unknown")

# --- Scan project ---
def scan_project(root_path: str) -> Dict[str, Any]:
    project_data = {"files": [], "languages": set()}
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            lang = detect_language(file_path)
            project_data["files"].append({
                "path": file_path,
                "language": lang,
                "extension": os.path.splitext(filename)[1]
            })
            if lang != "unknown":
                project_data["languages"].add(lang)
    return project_data

# --- Python structure ---
def extract_python_structure(file_path):
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append(node.name)
            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        globals_found.append(target.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    imports.extend([alias.name for alias in node.names])
                else:
                    imports.append(node.module)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- JavaScript structure ---
import esprima
def extract_javascript_structure(file_path: str) -> Dict[str, Any]:
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        ast_tree = esprima.parseModule(source)
        for node in ast_tree.body:
            if node.type == "ImportDeclaration":
                imports.append(node.source.value)
            elif node.type == "FunctionDeclaration" and node.id:
                functions.append(node.id.name)
            elif node.type == "ClassDeclaration" and node.id:
                classes.append(node.id.name)
            elif node.type == "VariableDeclaration":
                for decl in node.declarations:
                    if decl.id.type == "Identifier":
                        globals_found.append(decl.id.name)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- PHP structure ---
from phply.phplex import lexer as php_lexer
from phply.phpparse import make_parser as php_make_parser
def extract_php_structure(file_path: str) -> Dict[str, Any]:
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        parser = php_make_parser()
        ast_tree = parser.parse(code, lexer=php_lexer.clone())
        visited = set()

        def walk(node):
            node_id = id(node)
            if node_id in visited:
                return
            visited.add(node_id)
            if isinstance(node, list):
                for n in node: walk(n)
                return
            if not hasattr(node, "_class_"): return
            t = type(node)._name_
            if t == "Function":
                functions.append(node.name)
            elif t == "Class":
                classes.append(node.name)
            elif t == "Global":
                for g in getattr(node, "nodes", []):
                    globals_found.append(getattr(g, "name", None))
            elif t == "Include":
                imports.append(str(getattr(node, "expr", "")))
            for attr in dir(node):
                if attr.startswith("_"): continue
                val = getattr(node, attr, None)
                if isinstance(val, list) or hasattr(val, "_dict_"):
                    walk(val)
        walk(ast_tree)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- JSON structure ---
def extract_json_structure(file_path: str) -> Dict[str, Any]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        import re
        content = re.sub(r"//.*", "", content)
        content = re.sub(r"/\.?\*/", "", content, flags=re.S)
        data = _json.loads(content)
    except Exception:
        return {"keys": [], "secrets": []}

    keys, secrets = [], []
    def find(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(k)
                if any(s in k.lower() for s in ["secret", "token", "password", "key"]):
                    secrets.append({k: v})
                find(v)
        elif isinstance(obj, list):
            for entry in obj: find(entry)
    find(data)
    return {"keys": list(set(keys)), "secrets": secrets}

# --- .env structure ---
def extract_env_structure(file_path: str) -> Dict[str, Any]:
    variables, secrets = [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip()
                variables.append({key: value})
                if any(s in key.lower() for s in ["key", "secret", "token", "pass", "pwd"]):
                    secrets.append({key: value})
    except Exception:
        pass
    return {"variables": variables, "secrets": secrets}

# --- Process entire project ---
def process_project(root_path: str) -> Dict[str, Any]:
    project_info = scan_project(root_path)
    detailed_files = {}
    for file_entry in project_info["files"]:
        path = file_entry["path"]
        lang = file_entry["language"]

        if lang == "python":
            detailed_files[path] = extract_python_structure(path)
        elif lang == "javascript":
            detailed_files[path] = extract_javascript_structure(path)
        elif lang == "php":
            detailed_files[path] = extract_php_structure(path)
        elif lang == "json":
            detailed_files[path] = extract_json_structure(path)
        elif lang == "env":
            detailed_files[path] = extract_env_structure(path)
        else:
            detailed_files[path] = {"functions": [], "classes": [], "globals": [], "imports": []}

    return {"project_languages": list(project_info["languages"]), "files": detailed_files}

# --- Main execution ---
if __name__ == "_main_":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python input_processing.py <project_folder>")
        sys.exit(1)
    root = sys.argv[1]
    result = process_project(root)
    print(_json.dumps(result, indent=4))
