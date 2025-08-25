#!/usr/bin/env python3
"""
Code Complexity Analyzer

This script analyzes code complexity metrics for the PRS backend codebase
and enforces quality gates to maintain code quality standards.

Quality Standards:
- Core modules: < 100 lines per file
- Authentication modules: < 80 lines per file  
- General modules: < 200 lines per file
- No file should exceed 300 lines
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import re

# Add the Django project root to the path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent / "backend"
sys.path.insert(0, str(PROJECT_ROOT))

# Set Django settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")

try:
    import django
    django.setup()
except Exception as e:
    print(f"Warning: Could not setup Django: {e}")


@dataclass
class FileMetrics:
    """Metrics for a single Python file"""
    file_path: str
    line_count: int
    blank_lines: int
    comment_lines: int
    code_lines: int
    class_count: int
    function_count: int
    complexity_score: float
    maintainability_index: float
    imports_count: int
    max_function_length: int
    avg_function_length: float


@dataclass
class ModuleMetrics:
    """Aggregated metrics for a module/directory"""
    module_name: str
    total_files: int
    total_lines: int
    total_code_lines: int
    average_lines_per_file: float
    largest_file_lines: int
    largest_file_path: str
    complexity_score: float
    quality_grade: str
    files_exceeding_limits: List[str]


@dataclass
class QualityReport:
    """Complete quality analysis report"""
    timestamp: str
    project_root: str
    total_files: int
    total_lines: int
    quality_gates_passed: bool
    modules: List[ModuleMetrics]
    critical_files: List[FileMetrics]
    recommendations: List[str]
    summary: Dict[str, Any]


class CodeComplexityAnalyzer:
    """Analyzes code complexity metrics for Python files"""
    
    # Quality thresholds
    THRESHOLDS = {
        'core_config': {'max_lines': 100, 'target_complexity': 10},
        'authentication': {'max_lines': 80, 'target_complexity': 8},
        'apps': {'max_lines': 150, 'target_complexity': 12},
        'general': {'max_lines': 200, 'target_complexity': 15},
        'absolute_max': {'max_lines': 300, 'target_complexity': 20}
    }
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analysis_results: List[FileMetrics] = []
        
    def analyze_file(self, file_path: Path) -> FileMetrics:
        """Analyze a single Python file and return metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
        except (UnicodeDecodeError, FileNotFoundError, PermissionError) as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return FileMetrics(
                file_path=str(file_path.relative_to(self.project_root)),
                line_count=0, blank_lines=0, comment_lines=0, code_lines=0,
                class_count=0, function_count=0, complexity_score=0,
                maintainability_index=0, imports_count=0,
                max_function_length=0, avg_function_length=0
            )
        
        # Basic line counting
        line_count = len(lines)
        blank_lines = sum(1 for line in lines if not line.strip())
        comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
        code_lines = line_count - blank_lines - comment_lines
        
        # Count classes and functions
        class_count = len(re.findall(r'^class\s+\w+', content, re.MULTILINE))
        function_count = len(re.findall(r'^def\s+\w+', content, re.MULTILINE))
        
        # Count imports
        imports_count = len(re.findall(r'^(import|from)\s+', content, re.MULTILINE))
        
        # Calculate complexity metrics
        complexity_score = self._calculate_complexity(content)
        maintainability_index = self._calculate_maintainability_index(
            code_lines, complexity_score, function_count
        )
        
        # Function length analysis
        function_lengths = self._analyze_function_lengths(content)
        max_function_length = max(function_lengths) if function_lengths else 0
        avg_function_length = sum(function_lengths) / len(function_lengths) if function_lengths else 0
        
        return FileMetrics(
            file_path=str(file_path.relative_to(self.project_root)),
            line_count=line_count,
            blank_lines=blank_lines,
            comment_lines=comment_lines,
            code_lines=code_lines,
            class_count=class_count,
            function_count=function_count,
            complexity_score=complexity_score,
            maintainability_index=maintainability_index,
            imports_count=imports_count,
            max_function_length=max_function_length,
            avg_function_length=avg_function_length
        )
    
    def _calculate_complexity(self, content: str) -> float:
        """Calculate cyclomatic complexity estimate"""
        # Simple complexity calculation based on control structures
        complexity_patterns = [
            r'\bif\b', r'\belif\b', r'\belse\b',
            r'\bfor\b', r'\bwhile\b',
            r'\btry\b', r'\bexcept\b', r'\bfinally\b',
            r'\bwith\b', r'\band\b', r'\bor\b'
        ]
        
        total_complexity = 1  # Base complexity
        for pattern in complexity_patterns:
            total_complexity += len(re.findall(pattern, content))
        
        # Normalize by file size
        lines = len(content.splitlines())
        if lines > 0:
            return total_complexity / lines * 100
        return 0
    
    def _calculate_maintainability_index(self, lines: int, complexity: float, functions: int) -> float:
        """Calculate maintainability index (simplified)"""
        if lines == 0:
            return 100
        
        # Simplified maintainability index calculation
        # Higher is better (0-100 scale)
        base_score = 100
        
        # Penalize large files
        size_penalty = min(lines / 10, 30)
        
        # Penalize high complexity
        complexity_penalty = min(complexity * 2, 40)
        
        # Reward modular code (functions)
        function_bonus = min(functions, 10)
        
        score = base_score - size_penalty - complexity_penalty + function_bonus
        return max(0, min(100, score))
    
    def _analyze_function_lengths(self, content: str) -> List[int]:
        """Analyze function lengths in the file"""
        lines = content.splitlines()
        function_lengths = []
        current_function_length = 0
        in_function = False
        base_indent = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Check if we're starting a new function
            if stripped.startswith('def '):
                if in_function and current_function_length > 0:
                    function_lengths.append(current_function_length)
                
                in_function = True
                current_function_length = 1
                # Get the base indentation level
                base_indent = len(line) - len(line.lstrip())
            
            elif in_function:
                # Check if we're still in the function
                if stripped == '':
                    current_function_length += 1
                elif line.startswith(' ' * (base_indent + 1)) or stripped.startswith('"""') or stripped.startswith("'''"):
                    current_function_length += 1
                elif not stripped.startswith('#'):
                    # We've exited the function
                    if current_function_length > 0:
                        function_lengths.append(current_function_length)
                    in_function = False
                    current_function_length = 0
        
        # Don't forget the last function
        if in_function and current_function_length > 0:
            function_lengths.append(current_function_length)
        
        return function_lengths
    
    def analyze_module(self, module_path: Path, module_name: str) -> ModuleMetrics:
        """Analyze all Python files in a module directory"""
        python_files = list(module_path.rglob("*.py"))
        file_metrics = []
        
        for file_path in python_files:
            # Skip __pycache__ and migration files
            if "__pycache__" in str(file_path) or "/migrations/" in str(file_path):
                continue
            
            metrics = self.analyze_file(file_path)
            file_metrics.append(metrics)
        
        if not file_metrics:
            return ModuleMetrics(
                module_name=module_name,
                total_files=0, total_lines=0, total_code_lines=0,
                average_lines_per_file=0, largest_file_lines=0,
                largest_file_path="", complexity_score=0,
                quality_grade="N/A", files_exceeding_limits=[]
            )
        
        # Calculate aggregated metrics
        total_files = len(file_metrics)
        total_lines = sum(f.line_count for f in file_metrics)
        total_code_lines = sum(f.code_lines for f in file_metrics)
        average_lines_per_file = total_lines / total_files if total_files > 0 else 0
        
        # Find largest file
        largest_file = max(file_metrics, key=lambda f: f.line_count)
        largest_file_lines = largest_file.line_count
        largest_file_path = largest_file.file_path
        
        # Calculate average complexity
        complexity_score = sum(f.complexity_score for f in file_metrics) / total_files if total_files > 0 else 0
        
        # Determine quality grade
        quality_grade = self._calculate_quality_grade(module_name, file_metrics)
        
        # Find files exceeding limits
        files_exceeding_limits = self._find_files_exceeding_limits(module_name, file_metrics)
        
        return ModuleMetrics(
            module_name=module_name,
            total_files=total_files,
            total_lines=total_lines,
            total_code_lines=total_code_lines,
            average_lines_per_file=average_lines_per_file,
            largest_file_lines=largest_file_lines,
            largest_file_path=largest_file_path,
            complexity_score=complexity_score,
            quality_grade=quality_grade,
            files_exceeding_limits=files_exceeding_limits
        )
    
    def _calculate_quality_grade(self, module_name: str, file_metrics: List[FileMetrics]) -> str:
        """Calculate quality grade for a module"""
        # Get thresholds for this module
        thresholds = self._get_thresholds_for_module(module_name)
        
        # Count violations
        total_files = len(file_metrics)
        if total_files == 0:
            return "N/A"
        
        violations = 0
        for file_metric in file_metrics:
            if file_metric.line_count > thresholds['max_lines']:
                violations += 1
            if file_metric.complexity_score > thresholds['target_complexity']:
                violations += 1
        
        violation_rate = violations / (total_files * 2)  # 2 checks per file
        
        if violation_rate <= 0.1:
            return "A"
        elif violation_rate <= 0.25:
            return "B"
        elif violation_rate <= 0.5:
            return "C"
        elif violation_rate <= 0.75:
            return "D"
        else:
            return "F"
    
    def _get_thresholds_for_module(self, module_name: str) -> Dict[str, int]:
        """Get quality thresholds for a specific module"""
        module_lower = module_name.lower()
        
        if 'core_config' in module_lower:
            return self.THRESHOLDS['core_config']
        elif 'authentication' in module_lower:
            return self.THRESHOLDS['authentication']
        elif module_lower.startswith('apps/'):
            return self.THRESHOLDS['apps']
        else:
            return self.THRESHOLDS['general']
    
    def _find_files_exceeding_limits(self, module_name: str, file_metrics: List[FileMetrics]) -> List[str]:
        """Find files that exceed quality limits"""
        thresholds = self._get_thresholds_for_module(module_name)
        exceeding_files = []
        
        for file_metric in file_metrics:
            if file_metric.line_count > thresholds['max_lines']:
                exceeding_files.append(f"{file_metric.file_path} ({file_metric.line_count} lines)")
            elif file_metric.line_count > self.THRESHOLDS['absolute_max']['max_lines']:
                exceeding_files.append(f"{file_metric.file_path} ({file_metric.line_count} lines - CRITICAL)")
        
        return exceeding_files
    
    def analyze_project(self) -> QualityReport:
        """Analyze the entire project and generate a quality report"""
        modules = []
        all_file_metrics = []
        
        # Define modules to analyze
        module_paths = {
            "core_config": self.project_root / "core_config",
            "apps/authentication": self.project_root / "apps" / "authentication",
            "apps/deals": self.project_root / "apps" / "deals",
            "apps/commission": self.project_root / "apps" / "commission",
            "apps/clients": self.project_root / "apps" / "clients",
            "apps/notifications": self.project_root / "apps" / "notifications",
            "apps/organization": self.project_root / "apps" / "organization",
            "apps/permissions": self.project_root / "apps" / "permissions",
            "utils": self.project_root / "utils",
            "services": self.project_root / "services",
        }
        
        # Analyze each module
        for module_name, module_path in module_paths.items():
            if module_path.exists():
                module_metrics = self.analyze_module(module_path, module_name)
                modules.append(module_metrics)
                
                # Collect all file metrics for overall analysis
                python_files = list(module_path.rglob("*.py"))
                for file_path in python_files:
                    if "__pycache__" not in str(file_path) and "/migrations/" not in str(file_path):
                        file_metric = self.analyze_file(file_path)
                        all_file_metrics.append(file_metric)
        
        # Calculate overall metrics
        total_files = len(all_file_metrics)
        total_lines = sum(f.line_count for f in all_file_metrics)
        
        # Find critical files (very large or complex)
        critical_files = [
            f for f in all_file_metrics 
            if f.line_count > 200 or f.complexity_score > 15
        ]
        critical_files.sort(key=lambda f: f.line_count, reverse=True)
        
        # Check quality gates
        quality_gates_passed = self._check_quality_gates(modules, all_file_metrics)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(modules, critical_files)
        
        # Create summary
        summary = {
            "total_modules": len(modules),
            "modules_with_grade_a": len([m for m in modules if m.quality_grade == "A"]),
            "modules_with_grade_b": len([m for m in modules if m.quality_grade == "B"]),
            "modules_with_grade_c_or_below": len([m for m in modules if m.quality_grade in ["C", "D", "F"]]),
            "largest_file_lines": max((f.line_count for f in all_file_metrics), default=0),
            "average_lines_per_file": total_lines / total_files if total_files > 0 else 0,
            "files_exceeding_300_lines": len([f for f in all_file_metrics if f.line_count > 300]),
            "average_complexity": sum(f.complexity_score for f in all_file_metrics) / total_files if total_files > 0 else 0
        }
        
        return QualityReport(
            timestamp=datetime.now().isoformat(),
            project_root=str(self.project_root),
            total_files=total_files,
            total_lines=total_lines,
            quality_gates_passed=quality_gates_passed,
            modules=modules,
            critical_files=critical_files[:10],  # Top 10 critical files
            recommendations=recommendations,
            summary=summary
        )
    
    def _check_quality_gates(self, modules: List[ModuleMetrics], all_files: List[FileMetrics]) -> bool:
        """Check if quality gates pass"""
        # Critical failures
        if any(f.line_count > 500 for f in all_files):
            return False
        
        # Module-specific checks
        for module in modules:
            if module.module_name == "core_config" and module.largest_file_lines > 100:
                return False
            if module.module_name == "apps/authentication" and module.largest_file_lines > 80:
                return False
        
        # Overall quality check
        critical_files_count = len([f for f in all_files if f.line_count > 300])
        if critical_files_count > len(all_files) * 0.1:  # More than 10% of files are critical
            return False
        
        return True
    
    def _generate_recommendations(self, modules: List[ModuleMetrics], critical_files: List[FileMetrics]) -> List[str]:
        """Generate recommendations for code quality improvement"""
        recommendations = []
        
        # Analyze modules with poor grades
        poor_modules = [m for m in modules if m.quality_grade in ["D", "F"]]
        if poor_modules:
            recommendations.append(
                f"Priority: Refactor {len(poor_modules)} modules with poor quality grades: "
                f"{', '.join(m.module_name for m in poor_modules)}"
            )
        
        # Analyze critical files
        if critical_files:
            recommendations.append(
                f"Break down {len(critical_files)} critical files exceeding 200 lines"
            )
            
            # Specific file recommendations
            for file in critical_files[:3]:  # Top 3 most critical
                recommendations.append(
                    f"Refactor {file.file_path} ({file.line_count} lines) - "
                    f"consider breaking into {max(2, file.line_count // 150)} smaller modules"
                )
        
        # Module-specific recommendations
        for module in modules:
            if module.files_exceeding_limits:
                recommendations.append(
                    f"Module '{module.module_name}': {len(module.files_exceeding_limits)} files exceed limits"
                )
        
        if not recommendations:
            recommendations.append("Excellent! All quality gates are passing. Continue maintaining these standards.")
        
        return recommendations


def main():
    """Main entry point for the code complexity analyzer"""
    parser = argparse.ArgumentParser(description="Analyze code complexity and quality metrics")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--output", help="Output JSON file for the report")
    parser.add_argument("--fail-on-violations", action="store_true", help="Exit with error code if quality gates fail")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    project_root = Path(args.project_root).resolve()
    analyzer = CodeComplexityAnalyzer(str(project_root))
    
    print(f"🔍 Analyzing code quality for: {project_root}")
    print("=" * 60)
    
    # Run analysis
    try:
        report = analyzer.analyze_project()
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)
    
    # Print summary
    print(f"📊 QUALITY REPORT SUMMARY")
    print(f"Total Files: {report.total_files}")
    print(f"Total Lines: {report.total_lines:,}")
    print(f"Quality Gates: {'✅ PASSED' if report.quality_gates_passed else '❌ FAILED'}")
    print()
    
    # Print module grades
    print("📋 MODULE GRADES:")
    for module in sorted(report.modules, key=lambda m: m.quality_grade):
        status = "✅" if module.quality_grade in ["A", "B"] else "⚠️" if module.quality_grade == "C" else "❌"
        print(f"  {status} {module.module_name}: Grade {module.quality_grade} "
              f"({module.total_files} files, avg {module.average_lines_per_file:.1f} lines)")
    
    # Print critical files
    if report.critical_files:
        print(f"\n🚨 CRITICAL FILES ({len(report.critical_files)}):")
        for file in report.critical_files:
            print(f"  📄 {file.file_path}: {file.line_count} lines "
                  f"(complexity: {file.complexity_score:.1f})")
    
    # Print recommendations
    if report.recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(report.recommendations, 1):
            print(f"  {i}. {rec}")
    
    # Save report if requested
    if args.output:
        report_data = asdict(report)
        with open(args.output, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"\n💾 Report saved to: {args.output}")
    
    # Exit with error code if quality gates failed and requested
    if args.fail_on_violations and not report.quality_gates_passed:
        print("\n❌ Quality gates failed!")
        sys.exit(1)
    
    print(f"\n{'✅ Quality analysis completed successfully!' if report.quality_gates_passed else '⚠️ Quality issues detected - see recommendations above'}")


if __name__ == "__main__":
    main()
