"""
Base Security Checker
=====================

Base class for all framework-specific security checkers.
Provides common functionality and ensures consistent interface.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import re


class BaseSecurityChecker(ABC):
    """
    Abstract base class for security checkers.
    All framework-specific checkers should inherit from this class.
    """
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.supported_extensions = []
        self.severity_levels = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
    
    @abstractmethod
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Main check method - must be implemented by subclasses.
        
        Args:
            code: Source code content
            file_path: Path to the file being checked
            
        Returns:
            List of findings with structure:
            {
                "file": str,
                "issue": str,
                "severity": str (critical/high/medium/low/info),
                "type": str (config/exposure/misconfiguration),
                "line": int (optional),
                "recommendation": str (optional)
            }
        """
        pass
    
    def can_check_file(self, file_path: str, file_info: dict = None) -> bool:
        """
        Determine if this checker can analyze the given file.
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            True if checker can analyze this file, False otherwise
        """
        if not self.supported_extensions:
            return True
        
        return any(file_path.endswith(ext) for ext in self.supported_extensions)
    
    def create_finding(
        self,
        file_path: str,
        issue: str,
        severity: str = "medium",
        finding_type: str = "misconfiguration",
        line: int = None,
        recommendation: str = None
    ) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary.
        
        Args:
            file_path: Path to the file
            issue: Description of the security issue
            severity: Severity level (critical/high/medium/low/info)
            finding_type: Type of finding (config/exposure/misconfiguration)
            line: Optional line number
            recommendation: Optional fix recommendation
            
        Returns:
            Standardized finding dictionary
        """
        finding = {
            "file": file_path,
            "issue": issue,
            "severity": severity,
            "type": finding_type
        }
        
        if line is not None:
            finding["line"] = line
        
        if recommendation:
            finding["recommendation"] = recommendation
        
        return finding
    
    def find_pattern_in_code(self, code: str, pattern: str, flags: int = 0) -> List[Dict[str, Any]]:
        """
        Find all occurrences of a regex pattern in code.
        
        Args:
            code: Source code content
            pattern: Regex pattern to search for
            flags: Optional regex flags
            
        Returns:
            List of matches with line numbers and context
        """
        matches = []
        
        for match in re.finditer(pattern, code, flags):
            line_num = code[:match.start()].count('\n') + 1
            
            # Get surrounding context
            line_start = code.rfind('\n', 0, match.start()) + 1
            line_end = code.find('\n', match.end())
            if line_end == -1:
                line_end = len(code)
            
            context = code[line_start:line_end].strip()
            
            matches.append({
                'line': line_num,
                'match': match.group(0),
                'context': context
            })
        
        return matches
    
    def check_pattern_exists(self, code: str, pattern: str, flags: int = 0) -> bool:
        """
        Check if a pattern exists in code.
        
        Args:
            code: Source code content
            pattern: Regex pattern or string to search for
            flags: Optional regex flags
            
        Returns:
            True if pattern exists, False otherwise
        """
        if isinstance(pattern, str) and not any(c in pattern for c in r'.*+?[]{}()^$\|'):
            # Simple string search
            return pattern in code
        
        # Regex search
        return re.search(pattern, code, flags) is not None
    
    def get_line_number(self, code: str, text: str) -> int:
        """
        Get the line number where text appears in code.
        
        Args:
            code: Source code content
            text: Text to find
            
        Returns:
            Line number (1-indexed) or None if not found
        """
        try:
            index = code.index(text)
            return code[:index].count('\n') + 1
        except ValueError:
            return None



