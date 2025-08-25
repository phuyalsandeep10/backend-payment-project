#!/usr/bin/env python3
"""
Quality Gates Enforcement

This script enforces code quality gates in CI/CD pipelines and development workflows.
It can be integrated with pre-commit hooks, CI/CD systems, and IDE extensions.

Usage:
    # Check quality gates
    python quality_gates.py --check
    
    # Check specific module
    python quality_gates.py --check --module apps/authentication
    
    # Generate pre-commit hook
    python quality_gates.py --generate-pre-commit-hook
    
    # CI/CD integration
    python quality_gates.py --ci-mode --fail-build
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Import our complexity analyzer
sys.path.insert(0, str(Path(__file__).parent))
from code_complexity_analyzer import CodeComplexityAnalyzer, QualityReport


@dataclass 
class QualityGate:
    """Definition of a quality gate rule"""
    name: str
    description: str
    threshold: Any
    check_function: str
    severity: str  # 'error', 'warning', 'info'
    module_specific: Optional[str] = None


class QualityGateEnforcer:
    """Enforces quality gates and integrates with development workflows"""
    
    # Define quality gates
    QUALITY_GATES = [
        QualityGate(
            name="no_critical_files",
            description="No files should exceed 500 lines",
            threshold=500,
            check_function="check_no_critical_files",
            severity="error"
        ),
        QualityGate(
            name="core_config_complexity",
            description="Core config files must be under 100 lines",
            threshold=100,
            check_function="check_core_config_complexity",
            severity="error",
            module_specific="core_config"
        ),
        QualityGate(
            name="authentication_complexity",
            description="Authentication files must be under 80 lines",
            threshold=80,
            check_function="check_authentication_complexity",
            severity="error",
            module_specific="authentication"
        ),
        QualityGate(
            name="general_file_limit",
            description="General files should not exceed 300 lines",
            threshold=300,
            check_function="check_general_file_limit",
            severity="warning"
        ),
        QualityGate(
            name="module_quality_grade",
            description="Modules should maintain at least grade C",
            threshold="C",
            check_function="check_module_quality_grade",
            severity="warning"
        ),
        QualityGate(
            name="critical_file_ratio",
            description="Less than 10% of files should be critical (>200 lines)",
            threshold=0.10,
            check_function="check_critical_file_ratio",
            severity="warning"
        ),
        QualityGate(
            name="average_complexity",
            description="Average complexity should be under 10",
            threshold=10,
            check_function="check_average_complexity",
            severity="info"
        )
    ]
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analyzer = CodeComplexityAnalyzer(str(self.project_root))
        self.violations = []
        
    def check_quality_gates(self, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Check all quality gates and return results"""
        print("🔍 Running quality gate analysis...")
        
        # Run code analysis
        report = self.analyzer.analyze_project()
        
        # Check each quality gate
        results = {
            'passed': True,
            'gates': {},
            'violations': [],
            'summary': {
                'total_gates': len(self.QUALITY_GATES),
                'passed_gates': 0,
                'failed_gates': 0,
                'warning_gates': 0
            },
            'report': report
        }
        
        for gate in self.QUALITY_GATES:
            # Skip module-specific gates if filtering
            if modules and gate.module_specific and gate.module_specific not in modules:
                continue
                
            gate_result = self._check_single_gate(gate, report)
            results['gates'][gate.name] = gate_result
            
            if not gate_result['passed']:
                if gate.severity == 'error':
                    results['passed'] = False
                    results['summary']['failed_gates'] += 1
                elif gate.severity == 'warning':
                    results['summary']['warning_gates'] += 1
                
                results['violations'].append({
                    'gate': gate.name,
                    'severity': gate.severity,
                    'message': gate_result['message'],
                    'details': gate_result.get('details', [])
                })
            else:
                results['summary']['passed_gates'] += 1
        
        return results
    
    def _check_single_gate(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check a single quality gate"""
        check_method = getattr(self, gate.check_function, None)
        if not check_method:
            return {
                'passed': False,
                'message': f"Check method {gate.check_function} not found",
                'details': []
            }
        
        try:
            return check_method(gate, report)
        except Exception as e:
            return {
                'passed': False,
                'message': f"Error checking gate {gate.name}: {str(e)}",
                'details': []
            }
    
    # Quality gate check methods
    
    def check_no_critical_files(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check that no files exceed the critical size limit"""
        critical_files = [
            f for f in report.critical_files 
            if f.line_count > gate.threshold
        ]
        
        if critical_files:
            return {
                'passed': False,
                'message': f"{len(critical_files)} files exceed {gate.threshold} lines",
                'details': [f"{f.file_path}: {f.line_count} lines" for f in critical_files[:5]]
            }
        
        return {
            'passed': True,
            'message': f"All files are under {gate.threshold} lines",
            'details': []
        }
    
    def check_core_config_complexity(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check core_config module complexity"""
        core_config_module = next(
            (m for m in report.modules if 'core_config' in m.module_name.lower()),
            None
        )
        
        if not core_config_module:
            return {'passed': True, 'message': 'Core config module not found', 'details': []}
        
        if core_config_module.largest_file_lines > gate.threshold:
            return {
                'passed': False,
                'message': f"Core config largest file: {core_config_module.largest_file_lines} lines (limit: {gate.threshold})",
                'details': [f"File: {core_config_module.largest_file_path}"]
            }
        
        return {
            'passed': True,
            'message': f"Core config complexity OK (largest file: {core_config_module.largest_file_lines} lines)",
            'details': []
        }
    
    def check_authentication_complexity(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check authentication module complexity"""
        auth_module = next(
            (m for m in report.modules if 'authentication' in m.module_name.lower()),
            None
        )
        
        if not auth_module:
            return {'passed': True, 'message': 'Authentication module not found', 'details': []}
        
        if auth_module.largest_file_lines > gate.threshold:
            return {
                'passed': False,
                'message': f"Authentication largest file: {auth_module.largest_file_lines} lines (limit: {gate.threshold})",
                'details': [f"File: {auth_module.largest_file_path}"]
            }
        
        return {
            'passed': True,
            'message': f"Authentication complexity OK (largest file: {auth_module.largest_file_lines} lines)",
            'details': []
        }
    
    def check_general_file_limit(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check general file size limits"""
        large_files = [
            f for f in report.critical_files + [
                f for module in report.modules 
                for f in getattr(module, 'file_metrics', [])
            ] if hasattr(f, 'line_count') and f.line_count > gate.threshold
        ]
        
        if large_files:
            return {
                'passed': False,
                'message': f"{len(large_files)} files exceed {gate.threshold} lines",
                'details': [f"{f.file_path}: {f.line_count} lines" for f in large_files[:3]]
            }
        
        return {
            'passed': True,
            'message': f"All files are under {gate.threshold} lines",
            'details': []
        }
    
    def check_module_quality_grade(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check module quality grades"""
        poor_modules = [
            m for m in report.modules 
            if m.quality_grade in ['D', 'F']
        ]
        
        if poor_modules:
            return {
                'passed': False,
                'message': f"{len(poor_modules)} modules have poor quality grades",
                'details': [f"{m.module_name}: Grade {m.quality_grade}" for m in poor_modules]
            }
        
        return {
            'passed': True,
            'message': "All modules maintain acceptable quality grades",
            'details': []
        }
    
    def check_critical_file_ratio(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check ratio of critical files"""
        if report.total_files == 0:
            return {'passed': True, 'message': 'No files to analyze', 'details': []}
        
        critical_count = len([f for f in report.critical_files if f.line_count > 200])
        ratio = critical_count / report.total_files
        
        if ratio > gate.threshold:
            return {
                'passed': False,
                'message': f"Critical file ratio: {ratio:.1%} (limit: {gate.threshold:.1%})",
                'details': [f"{critical_count} critical files out of {report.total_files} total"]
            }
        
        return {
            'passed': True,
            'message': f"Critical file ratio OK: {ratio:.1%}",
            'details': []
        }
    
    def check_average_complexity(self, gate: QualityGate, report: QualityReport) -> Dict[str, Any]:
        """Check average complexity across the project"""
        avg_complexity = report.summary.get('average_complexity', 0)
        
        if avg_complexity > gate.threshold:
            return {
                'passed': False,
                'message': f"Average complexity: {avg_complexity:.1f} (limit: {gate.threshold})",
                'details': []
            }
        
        return {
            'passed': True,
            'message': f"Average complexity OK: {avg_complexity:.1f}",
            'details': []
        }
    
    def generate_pre_commit_hook(self, output_path: Optional[str] = None) -> str:
        """Generate a pre-commit hook script"""
        hook_content = '''#!/bin/bash
# Pre-commit quality gate hook
# Generated by quality_gates.py

echo "🔍 Running code quality checks..."

# Run quality gates
python scripts/quality/quality_gates.py --check --fail-on-error

if [ $? -ne 0 ]; then
    echo "❌ Quality gates failed! Commit blocked."
    echo "💡 Run 'python scripts/quality/quality_gates.py --check --verbose' for details"
    exit 1
fi

echo "✅ Quality gates passed!"
'''
        
        if output_path:
            hook_path = Path(output_path)
            hook_path.write_text(hook_content)
            hook_path.chmod(0o755)  # Make executable
            return str(hook_path)
        
        return hook_content
    
    def generate_github_action(self, output_path: Optional[str] = None) -> str:
        """Generate GitHub Actions workflow for quality gates"""
        action_content = '''name: Code Quality Gates

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  quality-gates:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run Quality Gates
      run: |
        cd Backend_PRS
        python scripts/quality/quality_gates.py --check --ci-mode --fail-build
    
    - name: Upload Quality Report
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: quality-report
        path: quality-report.json
'''
        
        if output_path:
            action_path = Path(output_path)
            action_path.parent.mkdir(parents=True, exist_ok=True)
            action_path.write_text(action_content)
            return str(action_path)
        
        return action_content
    
    def print_results(self, results: Dict[str, Any], verbose: bool = False):
        """Print quality gate results in a formatted way"""
        print("\n" + "=" * 60)
        print("🎯 QUALITY GATES RESULTS")
        print("=" * 60)
        
        # Overall status
        status = "✅ PASSED" if results['passed'] else "❌ FAILED"
        print(f"Overall Status: {status}")
        print()
        
        # Summary
        summary = results['summary']
        print("📊 SUMMARY:")
        print(f"  Total Gates: {summary['total_gates']}")
        print(f"  ✅ Passed: {summary['passed_gates']}")
        print(f"  ❌ Failed: {summary['failed_gates']}")
        print(f"  ⚠️  Warnings: {summary['warning_gates']}")
        print()
        
        # Gate details
        if verbose:
            print("🔍 GATE DETAILS:")
            for gate_name, gate_result in results['gates'].items():
                status_icon = "✅" if gate_result['passed'] else "❌"
                print(f"  {status_icon} {gate_name}: {gate_result['message']}")
                
                if gate_result.get('details'):
                    for detail in gate_result['details'][:3]:  # Show first 3 details
                        print(f"      - {detail}")
            print()
        
        # Violations
        if results['violations']:
            print("🚨 VIOLATIONS:")
            for violation in results['violations']:
                severity_icon = "❌" if violation['severity'] == 'error' else "⚠️"
                print(f"  {severity_icon} {violation['gate']}: {violation['message']}")
                
                if violation.get('details'):
                    for detail in violation['details']:
                        print(f"      - {detail}")
            print()


def main():
    """Main entry point for quality gates enforcement"""
    parser = argparse.ArgumentParser(description="Enforce code quality gates")
    parser.add_argument("--check", action="store_true", help="Check quality gates")
    parser.add_argument("--module", action="append", help="Check specific module(s)")
    parser.add_argument("--fail-on-error", action="store_true", help="Exit with error if gates fail")
    parser.add_argument("--fail-build", action="store_true", help="Exit with error for CI/CD (alias for --fail-on-error)")
    parser.add_argument("--ci-mode", action="store_true", help="CI/CD mode with JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--generate-pre-commit-hook", help="Generate pre-commit hook script")
    parser.add_argument("--generate-github-action", help="Generate GitHub Actions workflow")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    
    args = parser.parse_args()
    
    # Initialize enforcer
    project_root = Path(args.project_root).resolve()
    enforcer = QualityGateEnforcer(str(project_root))
    
    # Generate hooks/actions
    if args.generate_pre_commit_hook:
        hook_path = enforcer.generate_pre_commit_hook(args.generate_pre_commit_hook)
        print(f"✅ Pre-commit hook generated: {hook_path}")
        return
    
    if args.generate_github_action:
        action_path = enforcer.generate_github_action(args.generate_github_action)
        print(f"✅ GitHub Action generated: {action_path}")
        return
    
    # Check quality gates
    if args.check:
        try:
            results = enforcer.check_quality_gates(args.module)
        except Exception as e:
            print(f"❌ Error running quality gates: {e}")
            sys.exit(1)
        
        # Output results
        if args.ci_mode:
            print(json.dumps(results, indent=2, default=str))
        else:
            enforcer.print_results(results, args.verbose)
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Results saved to: {args.output}")
        
        # Exit with error if requested and gates failed
        if (args.fail_on_error or args.fail_build) and not results['passed']:
            print("\n❌ Quality gates failed!")
            sys.exit(1)
    
    else:
        # Show help if no action specified
        parser.print_help()


if __name__ == "__main__":
    main()
