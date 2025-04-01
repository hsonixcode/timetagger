#!/usr/bin/env python
"""
CodeLinter - A script to check for common code issues in the TimeTagger codebase.

This script checks for the following issues:
1. Bare except blocks (except: with no specific exception type)
2. Print statements (which should be replaced with logging)
3. # noqa comments (which might hide real issues)
4. TODO and FIXME comments (to track pending work)

Usage:
    python scripts/lint_code.py [--fix]

Options:
    --fix     Attempt to automatically fix some issues (currently print -> logging)
"""

import os
import re
import sys
import argparse
from typing import List, Tuple, Dict, Optional

# Regular expressions for finding issues
BARE_EXCEPT_RE = re.compile(r'\bexcept\s*:')
PRINT_STMT_RE = re.compile(r'\bprint\s*\(')
NOQA_RE = re.compile(r'# noqa')
TODO_RE = re.compile(r'# ?TODO')
FIXME_RE = re.compile(r'# ?FIXME')

# Statistics
stats = {
    'bare_except': 0,
    'print': 0,
    'noqa': 0,
    'todo': 0,
    'fixme': 0,
    'files_checked': 0,
    'files_with_issues': 0,
}

def find_python_files(root_dir: str) -> List[str]:
    """Find all Python files in the given directory and its subdirectories."""
    python_files = []
    
    for dirpath, _, filenames in os.walk(root_dir):
        # Skip __pycache__ directories and virtual environments
        if '__pycache__' in dirpath or 'venv' in dirpath or '.venv' in dirpath:
            continue
            
        for filename in filenames:
            if filename.endswith('.py'):
                full_path = os.path.join(dirpath, filename)
                python_files.append(full_path)
    
    return python_files

def check_file_for_issues(file_path: str, fix: bool = False) -> Dict[str, List[int]]:
    """Check a Python file for various code issues."""
    issues = {
        'bare_except': [],
        'print': [],
        'noqa': [],
        'todo': [],
        'fixme': [],
    }
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        if BARE_EXCEPT_RE.search(line):
            issues['bare_except'].append(i)
            stats['bare_except'] += 1
        
        if PRINT_STMT_RE.search(line):
            issues['print'].append(i)
            stats['print'] += 1
        
        if NOQA_RE.search(line):
            issues['noqa'].append(i)
            stats['noqa'] += 1
        
        if TODO_RE.search(line):
            issues['todo'].append(i)
            stats['todo'] += 1
        
        if FIXME_RE.search(line):
            issues['fixme'].append(i)
            stats['fixme'] += 1
    
    if fix:
        # If requested, try to automatically fix print statements
        if issues['print']:
            fixed_content = fix_print_statements(file_path, lines)
            if fixed_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                print(f"✓ Fixed print statements in {file_path}")
    
    return issues

def fix_print_statements(file_path: str, lines: List[str]) -> Optional[str]:
    """
    Attempt to fix print statements by converting them to logging calls.
    This is a simple transformation and may require manual review.
    """
    # Check if the file already imports logging
    has_logging_import = any('import logging' in line for line in lines)
    has_logger_setup = any('logger = logging.' in line for line in lines)
    
    # Create modified content
    fixed_lines = lines.copy()
    
    # Add logging import if needed
    if not has_logging_import:
        for i, line in enumerate(fixed_lines):
            if line.startswith('import ') or line.startswith('from '):
                fixed_lines.insert(i, 'import logging\n')
                break
    
    # Add logger setup if needed
    if not has_logger_setup:
        # Try to determine module name from file path
        module_parts = file_path.replace('\\', '/').split('/')
        if 'timetagger' in module_parts:
            idx = module_parts.index('timetagger')
            module_name = '.'.join(['timetagger'] + module_parts[idx+1:])
            module_name = module_name.replace('.py', '')
        else:
            module_name = os.path.basename(file_path).replace('.py', '')
        
        # Find a good place to insert the logger setup
        insert_pos = 0
        for i, line in enumerate(fixed_lines):
            if line.startswith('import '):
                insert_pos = i + 1
            elif line.startswith('from ') and insert_pos > 0:
                insert_pos = i + 1
        
        # Insert the logger setup
        fixed_lines.insert(insert_pos, f'\nlogger = logging.getLogger("{module_name}")\n')
    
    # Replace print statements with logging.info
    changes_made = False
    for i, line in enumerate(fixed_lines):
        if PRINT_STMT_RE.search(line):
            # Determine the indentation
            indent = len(line) - len(line.lstrip())
            indentation = line[:indent]
            
            # Replace print with logger.info
            # This is a simple replacement that works for basic cases
            # More complex print statements might need manual adjustment
            new_line = PRINT_STMT_RE.sub('logger.info(', line)
            fixed_lines[i] = new_line
            changes_made = True
    
    return ''.join(fixed_lines) if changes_made else None

def report_file_issues(file_path: str, issues: Dict[str, List[int]]) -> bool:
    """Report issues found in a file and return True if any issues were found."""
    has_issues = any(len(issue_lines) > 0 for issue_lines in issues.values())
    
    if not has_issues:
        return False
    
    # Show relative path for cleaner output
    rel_path = os.path.relpath(file_path)
    print(f"\n{rel_path}:")
    
    if issues['bare_except']:
        print(f"  ❌ Bare except blocks: Lines {', '.join(map(str, issues['bare_except']))}")
    
    if issues['print']:
        print(f"  ⚠️ Print statements: Lines {', '.join(map(str, issues['print']))}")
    
    if issues['noqa']:
        print(f"  ℹ️ # noqa comments: Lines {', '.join(map(str, issues['noqa']))}")
    
    if issues['todo']:
        print(f"  📝 TODO comments: Lines {', '.join(map(str, issues['todo']))}")
    
    if issues['fixme']:
        print(f"  🔧 FIXME comments: Lines {', '.join(map(str, issues['fixme']))}")
    
    return True

def print_summary():
    """Print a summary of all issues found."""
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Files checked: {stats['files_checked']}")
    print(f"Files with issues: {stats['files_with_issues']}")
    print("\nIssues found:")
    print(f"  ❌ Bare except blocks: {stats['bare_except']}")
    print(f"  ⚠️ Print statements: {stats['print']}")
    print(f"  ℹ️ # noqa comments: {stats['noqa']}")
    print(f"  📝 TODO comments: {stats['todo']}")
    print(f"  🔧 FIXME comments: {stats['fixme']}")
    print("=" * 50)
    
    if stats['bare_except'] > 0:
        print("\nRecommendation: Fix bare except blocks by adding specific exception types.")
    
    if stats['print'] > 0:
        print("\nRecommendation: Replace print statements with proper logging.")
    
    if stats['noqa'] > 0:
        print("\nRecommendation: Review # noqa comments to determine if they can be removed.")

def main():
    parser = argparse.ArgumentParser(description="Check for code issues in the TimeTagger codebase")
    parser.add_argument('--fix', action='store_true', help='Attempt to automatically fix some issues')
    args = parser.parse_args()
    
    # Define the root directory (assuming the script is in the scripts/ folder)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Find all Python files
    python_files = find_python_files(root_dir)
    stats['files_checked'] = len(python_files)
    
    print(f"Checking {len(python_files)} Python files for issues...")
    
    # Check each file
    for file_path in python_files:
        issues = check_file_for_issues(file_path, fix=args.fix)
        if report_file_issues(file_path, issues):
            stats['files_with_issues'] += 1
    
    # Print summary
    print_summary()
    
    # Return non-zero exit code if critical issues were found
    if stats['bare_except'] > 0:
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 