#!/usr/bin/env python3
"""
Code Injection Detector - Multi-language code-based prompt injection detection

Detects code-based prompt injection attacks across 9+ programming languages including:
- Direct code execution attempts
- Obfuscated payloads (base64, hex, Unicode)
- Multi-language exploits (polyglot code)
- RAG poisoning attempts
- Agent manipulation through code

Detection strategy:
  Each language has "fingerprint" patterns unique to that language.
  A language is only reported if at least one fingerprint matches.
  Generic patterns (eval, exec, system) alone are NOT enough to label a language
  since they appear in multiple languages — but they still trigger threat_detected.
"""

import re
from typing import Dict, List, Any
from datetime import datetime


class CodeInjectionDetector:
    """
    Detects code-based prompt injection attacks across multiple programming languages.

    Uses language fingerprints (unique syntax per language) to accurately identify
    which language is being used, avoiding false positives from shared function names.
    """

    def __init__(self):
        self.language_fingerprints = self._load_fingerprints()
        self.generic_threat_patterns = self._load_generic_threats()

    def _load_fingerprints(self) -> Dict[str, List[re.Pattern]]:
        """
        Language fingerprints: patterns that are UNIQUE to each language.
        A language is only reported when at least one fingerprint matches.
        """
        return {
            # POWERSHELL - cmdlet verb-noun syntax, PS variables, .NET types
            'PowerShell': [
                re.compile(r'\bInvoke-Expression\b', re.IGNORECASE),
                re.compile(r'\bInvoke-Command\b', re.IGNORECASE),
                re.compile(r'\bInvoke-WebRequest\b', re.IGNORECASE),
                re.compile(r'\biex\s+[\$\("]', re.IGNORECASE),     # iex followed by PS tokens
                re.compile(r'\bStart-Process\b', re.IGNORECASE),
                re.compile(r'\bNew-Object\b', re.IGNORECASE),
                re.compile(r'\bAdd-Type\b', re.IGNORECASE),
                re.compile(r'\bGet-\w+\b', re.IGNORECASE),          # Get-ChildItem, Get-Content, etc.
                re.compile(r'\bSet-\w+\b', re.IGNORECASE),          # Set-ExecutionPolicy, etc.
                re.compile(r'\bWrite-Host\b|\bWrite-Output\b|\bWrite-Error\b', re.IGNORECASE),
                re.compile(r'\bpowershell(?:\.exe)?\s+-', re.IGNORECASE),
                re.compile(r'-EncodedCommand\b', re.IGNORECASE),
                re.compile(r'-ExecutionPolicy\b', re.IGNORECASE),
                re.compile(r'\[System\.', re.IGNORECASE),            # .NET type [System.IO.File]
                re.compile(r'\[Net\.WebClient\]', re.IGNORECASE),
                re.compile(r'\bDownloadString\b', re.IGNORECASE),
                re.compile(r'\bDownloadFile\b', re.IGNORECASE),
                re.compile(r'\$\w+\s*=\s*New-Object\b', re.IGNORECASE),
                re.compile(r'\$PSVersionTable\b', re.IGNORECASE),
                re.compile(r'\$ErrorActionPreference\b', re.IGNORECASE),
                re.compile(r'\bForEach-Object\b|\bWhere-Object\b|\bSelect-Object\b', re.IGNORECASE),
                re.compile(r'\bOut-File\b|\bOut-String\b|\bOut-Null\b', re.IGNORECASE),
                re.compile(r'&\s*\{\s*', re.IGNORECASE),            # Script block & { ... }
                re.compile(r'\bparam\s*\(', re.IGNORECASE),         # PS function param block
                re.compile(r'\bRemove-Item\b|\bCopy-Item\b|\bMove-Item\b', re.IGNORECASE),
            ],

            # PYTHON - import system, dunder attributes, f-strings, Python-specific builtins
            'Python': [
                re.compile(r'\b__import__\s*\(', re.IGNORECASE),
                re.compile(r'\b__builtins__\b', re.IGNORECASE),
                re.compile(r'\b__class__\b', re.IGNORECASE),
                re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
                re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
                re.compile(r'\bos\.execv\b|\bos\.execve\b', re.IGNORECASE),
                re.compile(r'\bsubprocess\.(call|run|Popen|check_output|check_call)\b', re.IGNORECASE),
                re.compile(r'\bimport\s+os\b', re.IGNORECASE),
                re.compile(r'\bimport\s+subprocess\b', re.IGNORECASE),
                re.compile(r'\bfrom\s+os\s+import\b', re.IGNORECASE),
                re.compile(r'\bfrom\s+subprocess\s+import\b', re.IGNORECASE),
                re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
                re.compile(r'\bglobals\s*\(\)', re.IGNORECASE),
                re.compile(r'\blocals\s*\(\)', re.IGNORECASE),
                re.compile(r'\bgetattr\s*\(', re.IGNORECASE),
                re.compile(r'\bsetattr\s*\(', re.IGNORECASE),
                re.compile(r'\bcompile\s*\([^,]+,\s*["\'][^"\']*["\'],', re.IGNORECASE),  # compile(src, filename, mode)
                re.compile(r'f["\'][^"\']*\{[^}]+\}', re.IGNORECASE),  # f-strings
                re.compile(r'\bprint\s*\(', re.IGNORECASE),            # Python 3 print()
                re.compile(r'\bpickle\.loads?\s*\(', re.IGNORECASE),
                re.compile(r'\byaml\.load\s*\(', re.IGNORECASE),
                re.compile(r'\beval\s*\(.*\bcompile\b', re.IGNORECASE),  # eval(compile(...))
            ],

            # SHELL/BASH - shebang, pipe-to-shell, shell variable syntax
            'Shell/Bash': [
                re.compile(r'#!\s*/bin/(bash|sh|zsh|ksh|dash)', re.IGNORECASE),
                re.compile(r'\b/bin/(sh|bash|zsh)\b'),
                re.compile(r'\bbash\s+-c\b', re.IGNORECASE),
                re.compile(r'\bsh\s+-c\b', re.IGNORECASE),
                re.compile(r'\|\s*(sh|bash|zsh)\b', re.IGNORECASE),    # | bash
                re.compile(r';\s*(sh|bash)\b', re.IGNORECASE),
                re.compile(r'\b(curl|wget)\s+.*\|\s*(bash|sh)', re.IGNORECASE),
                re.compile(r'\brm\s+-rf\b', re.IGNORECASE),
                re.compile(r'\bchmod\s+[0-7]{3,4}\b', re.IGNORECASE),
                re.compile(r'\bexport\s+\w+=', re.IGNORECASE),
                re.compile(r'\$\(.*\)', re.IGNORECASE),                 # command substitution $(...)
                re.compile(r'\$\{\w+\}', re.IGNORECASE),               # shell variable ${VAR}
                re.compile(r'\becho\s+.*>>', re.IGNORECASE),            # append redirect
                re.compile(r'2>&1'),                                    # stderr redirect
                re.compile(r'\bsource\s+\S+\.sh\b', re.IGNORECASE),
                re.compile(r'\b\.\s+\S+\.sh\b', re.IGNORECASE),       # . script.sh
                re.compile(r'\bif\s+\[.*\]\s*;\s*then\b', re.IGNORECASE),
                re.compile(r'\bfor\s+\w+\s+in\s+\$', re.IGNORECASE),  # for x in $LIST
                re.compile(r'\bwhile\s+read\b', re.IGNORECASE),
                re.compile(r'\bnohup\b|\bsudo\b|\bsu\b\s+-[lc]', re.IGNORECASE),
                re.compile(r'\bcat\s+/etc/(passwd|shadow|hosts)\b', re.IGNORECASE),
            ],

            # SQL - keyword combinations unique to SQL
            'SQL': [
                re.compile(r'\bUNION\s+(ALL\s+)?SELECT\b', re.IGNORECASE),
                re.compile(r'\bDROP\s+TABLE\b', re.IGNORECASE),
                re.compile(r'\bDROP\s+DATABASE\b', re.IGNORECASE),
                re.compile(r'\bTRUNCATE\s+TABLE\b', re.IGNORECASE),
                re.compile(r'\bINSERT\s+INTO\b', re.IGNORECASE),
                re.compile(r'\bSELECT\s+.*\bFROM\b', re.IGNORECASE),
                re.compile(r'\bxp_cmdshell\b', re.IGNORECASE),
                re.compile(r'\bEXEC\s+master\b', re.IGNORECASE),
                re.compile(r'\bINTO\s+OUTFILE\b', re.IGNORECASE),
                re.compile(r'\bLOAD_FILE\s*\(', re.IGNORECASE),
                re.compile(r"'\s*OR\s+'?1'?\s*=\s*'?1'?", re.IGNORECASE),
                re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE),
                re.compile(r'\bSLEEP\s*\(\s*\d+\s*\)', re.IGNORECASE),
                re.compile(r'\bWAITFOR\s+DELAY\b', re.IGNORECASE),
                re.compile(r'\bBENCHMARK\s*\(', re.IGNORECASE),
                re.compile(r'--\s*$', re.MULTILINE),                   # SQL comment at end of line
                re.compile(r"'\s*;\s*\bDROP\b", re.IGNORECASE),
            ],

            # JAVA - Java-specific runtime and reflection API
            'Java': [
                re.compile(r'\bRuntime\.getRuntime\s*\(\)', re.IGNORECASE),
                re.compile(r'\bnew\s+ProcessBuilder\s*\(', re.IGNORECASE),
                re.compile(r'\bClass\.forName\s*\(', re.IGNORECASE),
                re.compile(r'\.getDeclaredMethod\s*\(', re.IGNORECASE),
                re.compile(r'\.getDeclaredField\s*\(', re.IGNORECASE),
                re.compile(r'\.newInstance\s*\(\)', re.IGNORECASE),
                re.compile(r'\bScriptEngineManager\b', re.IGNORECASE),
                re.compile(r'\bObjectInputStream\b', re.IGNORECASE),
                re.compile(r'\.readObject\s*\(\)', re.IGNORECASE),
                re.compile(r'\bThread\.sleep\s*\(', re.IGNORECASE),
                re.compile(r'\bSystem\.exit\s*\(', re.IGNORECASE),
                re.compile(r'\bimport\s+java\.lang\.reflect\b', re.IGNORECASE),
                re.compile(r'\bimport\s+java\.io\b', re.IGNORECASE),
            ],

            # PHP - PHP-specific syntax and superglobals
            'PHP': [
                re.compile(r'<\?php\b', re.IGNORECASE),
                re.compile(r'\$_GET\s*\[', re.IGNORECASE),
                re.compile(r'\$_POST\s*\[', re.IGNORECASE),
                re.compile(r'\$_REQUEST\s*\[', re.IGNORECASE),
                re.compile(r'\$_SERVER\s*\[', re.IGNORECASE),
                re.compile(r'\bshell_exec\s*\(', re.IGNORECASE),
                re.compile(r'\bpassthru\s*\(', re.IGNORECASE),
                re.compile(r'\bproc_open\s*\(', re.IGNORECASE),
                re.compile(r'\bphpinfo\s*\(\)', re.IGNORECASE),
                re.compile(r'\bbase64_decode\s*\(', re.IGNORECASE),
                re.compile(r'\bstr_rot13\s*\(', re.IGNORECASE),
                re.compile(r'\bfile_get_contents\s*\(', re.IGNORECASE),
                re.compile(r'\binclude_once\b|\brequire_once\b', re.IGNORECASE),
                re.compile(r'\bpreg_replace\s*\(\s*["\'].*["\'].*["\']e["\']', re.IGNORECASE),  # /e modifier RCE
                re.compile(r'\becho\s+\$', re.IGNORECASE),            # echo $variable
                re.compile(r'\bvar_dump\s*\(', re.IGNORECASE),
                re.compile(r'\bheader\s*\(', re.IGNORECASE),
            ],

            # RUBY - Ruby-specific methods and syntax
            'Ruby': [
                re.compile(r'\bKernel\.eval\b', re.IGNORECASE),
                re.compile(r'\.instance_eval\s*\{', re.IGNORECASE),
                re.compile(r'\.class_eval\s*\{', re.IGNORECASE),
                re.compile(r'\bIO\.popen\s*\(', re.IGNORECASE),
                re.compile(r'\bOpen3\.\w+', re.IGNORECASE),
                re.compile(r'\bspawn\s*\(', re.IGNORECASE),
                re.compile(r'\bputs\s+', re.IGNORECASE),
                re.compile(r'\brequire\s+["\']base64["\']', re.IGNORECASE),
                re.compile(r'\brequire\s+["\']open3["\']', re.IGNORECASE),
                re.compile(r'\.each\s+do\s*\|', re.IGNORECASE),      # block syntax
                re.compile(r'\bdo\s*\|\w+\|\s*$', re.MULTILINE),
                re.compile(r'\bend\b\s*$', re.MULTILINE),
                re.compile(r'%x\{[^}]+\}', re.IGNORECASE),           # %x{command} shell exec
                re.compile(r'%x\[[^\]]+\]', re.IGNORECASE),
                re.compile(r'\bopen\s*\(\s*["\'][|]', re.IGNORECASE),  # open('|command')
            ],

            # GO - Go-specific syntax
            'Go': [
                re.compile(r'\bexec\.Command\s*\(', re.IGNORECASE),
                re.compile(r'\bos/exec\b', re.IGNORECASE),
                re.compile(r'\bsyscall\.Exec\s*\(', re.IGNORECASE),
                re.compile(r'\bsyscall\.ForkExec\s*\(', re.IGNORECASE),
                re.compile(r'\bC\.system\s*\(', re.IGNORECASE),
                re.compile(r'import\s+"os/exec"', re.IGNORECASE),
                re.compile(r'import\s+"syscall"', re.IGNORECASE),
                re.compile(r'\bfmt\.Println\s*\(', re.IGNORECASE),
                re.compile(r'\bfunc\s+main\s*\(\s*\)', re.IGNORECASE),
                re.compile(r'\bgo\s+func\s*\(', re.IGNORECASE),      # goroutine
            ],

            # C/C++ - system headers and low-level calls
            'C/C++': [
                re.compile(r'#include\s*<\s*(stdio|stdlib|unistd|sys/types)\.h\s*>', re.IGNORECASE),
                re.compile(r'\bexecve\s*\(', re.IGNORECASE),
                re.compile(r'\bexecvp\s*\(', re.IGNORECASE),
                re.compile(r'\bexecl\s*\(', re.IGNORECASE),
                re.compile(r'\bfork\s*\(\)', re.IGNORECASE),
                re.compile(r'\bint\s+main\s*\(', re.IGNORECASE),
                re.compile(r'\bprintf\s*\(', re.IGNORECASE),
                re.compile(r'\bscanf\s*\(', re.IGNORECASE),
                re.compile(r'\bvoid\s*\*\s*\w+', re.IGNORECASE),     # void pointer
                re.compile(r'\bmalloc\s*\(|\bfree\s*\(', re.IGNORECASE),
                re.compile(r'\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(', re.IGNORECASE),
            ],

            # JAVASCRIPT/NODE - browser/Node APIs (unique JS patterns only, not bare eval)
            'JavaScript': [
                re.compile(r'\bnew\s+Function\s*\(', re.IGNORECASE),
                re.compile(r'\bFunction\s*\(\s*["\']', re.IGNORECASE),
                re.compile(r'\bsetTimeout\s*\(["\']', re.IGNORECASE),  # setTimeout('eval...')
                re.compile(r'\bsetInterval\s*\(["\']', re.IGNORECASE),
                re.compile(r'\bdocument\.write\s*\(', re.IGNORECASE),
                re.compile(r'\binnerHTML\s*=', re.IGNORECASE),
                re.compile(r'\brequire\s*\(\s*["\']child_process["\']', re.IGNORECASE),
                re.compile(r'\bprocess\.env\b', re.IGNORECASE),
                re.compile(r'\bchild_process\.(exec|spawn|execSync)\b', re.IGNORECASE),
                re.compile(r'\bconsole\.(log|error|warn)\s*\(', re.IGNORECASE),
                re.compile(r'\bwindow\.(location|eval)\b', re.IGNORECASE),
                re.compile(r'\bString\.fromCharCode\s*\(', re.IGNORECASE),
                re.compile(r'\batob\s*\(|\bbtoa\s*\(', re.IGNORECASE),
            ],

            # OBFUSCATION - encoding/encoding-agnostic threats
            'Obfuscation': [
                re.compile(r'\bbase64\.b64decode\s*\(', re.IGNORECASE),
                re.compile(r'\bBase64\.decode\s*\(', re.IGNORECASE),
                re.compile(r'[A-Za-z0-9+/]{60,}={0,2}',),            # Long base64 strings (60+ chars)
                re.compile(r'\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}', re.IGNORECASE),  # Sequence of hex escapes
                re.compile(r'(0x[0-9a-f]{2},?\s*){4,}', re.IGNORECASE),  # Hex byte array
                re.compile(r'\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){2,}', re.IGNORECASE),  # Unicode escape sequence
                re.compile(r'[\u200B-\u200D\u2060\u180E\uFEFF]'),    # Zero-width characters
                re.compile(r'%[0-9a-f]{2}(%[0-9a-f]{2}){3,}', re.IGNORECASE),  # URL encoding sequence
            ],

            # RAG POISONING - injection through document context
            'RAG_Poisoning': [
                re.compile(r'according\s+to.*\b(eval|exec|system)\s*\(', re.IGNORECASE),
                re.compile(r'document\s+states.*\b(eval|exec|system)\s*\(', re.IGNORECASE),
                re.compile(r'source\s+says.*\b(eval|exec|system)\s*\(', re.IGNORECASE),
                re.compile(r'context\s*:\s*.*\b(eval|exec|system)\s*\(', re.IGNORECASE),
                re.compile(r'```[^`]*\b(eval|exec|system)\s*\([^`]*```', re.IGNORECASE | re.DOTALL),
            ],

            # AGENT MANIPULATION - code-based attempts to probe or override AI agent behaviour.
            # Linguistic jailbreaks and persona overrides belong in unknown-malicious-intent-detector.
            'Agent_Manipulation': [
                re.compile(r'print\s*\(.*system.*prompt', re.IGNORECASE),
                re.compile(r'console\.log\s*\(.*instructions', re.IGNORECASE),
            ],
        }

    def _load_generic_threats(self) -> List[re.Pattern]:
        """
        Generic code execution patterns that indicate a threat exists
        but are too ambiguous to label a specific language.
        Used to set threat_detected=True without mislabeling.
        """
        return [
            re.compile(r'\beval\s*\(', re.IGNORECASE),
            re.compile(r'\bexec\s*\(', re.IGNORECASE),
            re.compile(r'\bsystem\s*\(\s*["\']', re.IGNORECASE),   # system('...') — generic call with string
            re.compile(r'`[^`]{3,}`'),                              # backtick execution (3+ chars)
        ]

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a prompt for code-based injection attacks.

        Returns:
            {
                'threat_detected': bool,
                'code_types': List[str],   # Languages/categories with fingerprint matches
                'threat_count': int,       # Number of distinct matched language categories
                'timestamp': str
            }
        """
        if not prompt or not isinstance(prompt, str):
            return {
                'threat_detected': False,
                'code_types': [],
                'threat_count': 0,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'error': 'Invalid input: prompt must be a non-empty string'
            }

        try:
            detected_types = set()
            generic_threat = False

            # Check language fingerprints — only report a language if its unique pattern matches
            for language, patterns in self.language_fingerprints.items():
                for pattern in patterns:
                    try:
                        if pattern.search(prompt):
                            detected_types.add(language)
                            break  # One fingerprint match is enough to identify this language
                    except Exception:
                        pass

            # Check generic threats — these set threat_detected but don't add a language label
            for pattern in self.generic_threat_patterns:
                try:
                    if pattern.search(prompt):
                        generic_threat = True
                        break
                except Exception:
                    pass

            threat_detected = len(detected_types) > 0 or generic_threat

            return {
                'threat_detected': threat_detected,
                'code_types': sorted(detected_types),
                'threat_count': len(detected_types),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }

        except Exception as e:
            return {
                'error': True,
                'error_message': f'Analysis failed: {str(e)}',
                'threat_detected': None,
                'code_types': [],
                'threat_count': 0,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }

    def analyze_batch(self, prompts: List[str]) -> List[Dict[str, Any]]:
        if not prompts or not isinstance(prompts, list):
            return []
        return [self.analyze(prompt) for prompt in prompts]


# Standalone CLI interface
if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python code_injection_detector.py <prompt_text>")
        print("   or: python code_injection_detector.py --batch <file_path>")
        sys.exit(1)

    detector = CodeInjectionDetector()

    if sys.argv[1] == '--batch' and len(sys.argv) > 2:
        try:
            with open(sys.argv[2], 'r', encoding='utf-8') as f:
                prompts = [line.strip() for line in f if line.strip()]
            results = detector.analyze_batch(prompts)
            print(json.dumps(results, indent=2))
        except Exception as e:
            print(f"Error reading batch file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        prompt = ' '.join(sys.argv[1:])
        result = detector.analyze(prompt)
        print(json.dumps(result, indent=2))
