#!/usr/bin/env python3
"""
Quality Reporting Dashboard

This script generates comprehensive quality reports with visualizations
and can track quality metrics over time.

Features:
- HTML dashboard with charts and metrics
- Historical trend tracking
- Module comparison reports
- Quality improvement recommendations
- Export to various formats (HTML, PDF, JSON)

Usage:
    # Generate HTML dashboard
    python quality_dashboard.py --generate-dashboard
    
    # Track quality over time
    python quality_dashboard.py --track-history
    
    # Compare modules
    python quality_dashboard.py --compare-modules
    
    # Export report
    python quality_dashboard.py --export pdf --output quality-report.pdf
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse
from dataclasses import dataclass, asdict

# Import our analyzers
sys.path.insert(0, str(Path(__file__).parent))
from code_complexity_analyzer import CodeComplexityAnalyzer, QualityReport
from quality_gates import QualityGateEnforcer


@dataclass
class QualitySnapshot:
    """A point-in-time snapshot of quality metrics"""
    timestamp: str
    commit_hash: Optional[str]
    total_files: int
    total_lines: int
    average_lines_per_file: float
    critical_files_count: int
    modules_grade_a: int
    modules_grade_b: int
    modules_grade_c_or_below: int
    quality_gates_passed: bool
    overall_complexity: float


class QualityDatabase:
    """SQLite database for storing quality metrics over time"""
    
    def __init__(self, db_path: str = "quality_metrics.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize the quality metrics database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Quality snapshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quality_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                commit_hash TEXT,
                total_files INTEGER,
                total_lines INTEGER,
                average_lines_per_file REAL,
                critical_files_count INTEGER,
                modules_grade_a INTEGER,
                modules_grade_b INTEGER,
                modules_grade_c_or_below INTEGER,
                quality_gates_passed BOOLEAN,
                overall_complexity REAL
            )
        ''')
        
        # Module metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS module_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER,
                module_name TEXT,
                total_files INTEGER,
                total_lines INTEGER,
                quality_grade TEXT,
                complexity_score REAL,
                FOREIGN KEY (snapshot_id) REFERENCES quality_snapshots (id)
            )
        ''')
        
        # File metrics table  
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER,
                file_path TEXT,
                line_count INTEGER,
                complexity_score REAL,
                maintainability_index REAL,
                FOREIGN KEY (snapshot_id) REFERENCES quality_snapshots (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_snapshot(self, report: QualityReport) -> int:
        """Save a quality snapshot to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get current commit hash if available
        commit_hash = self._get_current_commit_hash()
        
        # Create snapshot
        snapshot = QualitySnapshot(
            timestamp=report.timestamp,
            commit_hash=commit_hash,
            total_files=report.total_files,
            total_lines=report.total_lines,
            average_lines_per_file=report.summary.get('average_lines_per_file', 0),
            critical_files_count=len(report.critical_files),
            modules_grade_a=report.summary.get('modules_with_grade_a', 0),
            modules_grade_b=report.summary.get('modules_with_grade_b', 0),
            modules_grade_c_or_below=report.summary.get('modules_with_grade_c_or_below', 0),
            quality_gates_passed=report.quality_gates_passed,
            overall_complexity=report.summary.get('average_complexity', 0)
        )
        
        # Insert snapshot
        cursor.execute('''
            INSERT INTO quality_snapshots 
            (timestamp, commit_hash, total_files, total_lines, average_lines_per_file,
             critical_files_count, modules_grade_a, modules_grade_b, modules_grade_c_or_below,
             quality_gates_passed, overall_complexity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            snapshot.timestamp, snapshot.commit_hash, snapshot.total_files,
            snapshot.total_lines, snapshot.average_lines_per_file,
            snapshot.critical_files_count, snapshot.modules_grade_a,
            snapshot.modules_grade_b, snapshot.modules_grade_c_or_below,
            snapshot.quality_gates_passed, snapshot.overall_complexity
        ))
        
        snapshot_id = cursor.lastrowid
        
        # Insert module metrics
        for module in report.modules:
            cursor.execute('''
                INSERT INTO module_metrics 
                (snapshot_id, module_name, total_files, total_lines, quality_grade, complexity_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (snapshot_id, module.module_name, module.total_files,
                  module.total_lines, module.quality_grade, module.complexity_score))
        
        # Insert file metrics
        for file_metric in report.critical_files:
            cursor.execute('''
                INSERT INTO file_metrics
                (snapshot_id, file_path, line_count, complexity_score, maintainability_index)
                VALUES (?, ?, ?, ?, ?)
            ''', (snapshot_id, file_metric.file_path, file_metric.line_count,
                  file_metric.complexity_score, file_metric.maintainability_index))
        
        conn.commit()
        conn.close()
        
        return snapshot_id
    
    def get_historical_snapshots(self, days: int = 30) -> List[QualitySnapshot]:
        """Get historical quality snapshots"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute('''
            SELECT * FROM quality_snapshots 
            WHERE timestamp >= ? 
            ORDER BY timestamp DESC
        ''', (since_date,))
        
        snapshots = []
        for row in cursor.fetchall():
            snapshot = QualitySnapshot(
                timestamp=row[1], commit_hash=row[2], total_files=row[3],
                total_lines=row[4], average_lines_per_file=row[5],
                critical_files_count=row[6], modules_grade_a=row[7],
                modules_grade_b=row[8], modules_grade_c_or_below=row[9],
                quality_gates_passed=bool(row[10]), overall_complexity=row[11]
            )
            snapshots.append(snapshot)
        
        conn.close()
        return snapshots
    
    def _get_current_commit_hash(self) -> Optional[str]:
        """Get current Git commit hash"""
        try:
            import subprocess
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None


class QualityReportGenerator:
    """Generates various quality reports and dashboards"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.db = QualityDatabase(str(self.project_root / "quality_metrics.db"))
    
    def generate_html_dashboard(self, output_path: str) -> str:
        """Generate an HTML dashboard with quality metrics"""
        # Run current analysis
        analyzer = CodeComplexityAnalyzer(str(self.project_root))
        current_report = analyzer.analyze_project()
        
        # Save to database for historical tracking
        self.db.save_snapshot(current_report)
        
        # Get historical data
        historical_snapshots = self.db.get_historical_snapshots(30)
        
        # Generate HTML
        html_content = self._generate_html_template(current_report, historical_snapshots)
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html_content)
        
        return str(output_file)
    
    def _generate_html_template(self, report: QualityReport, 
                               historical_snapshots: List[QualitySnapshot]) -> str:
        """Generate HTML dashboard template"""
        
        # Generate charts data
        trend_data = self._generate_trend_data(historical_snapshots)
        module_data = self._generate_module_data(report)
        critical_files_data = self._generate_critical_files_data(report)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Quality Dashboard - PRS Backend</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }}
        .status-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .status-pass {{ background-color: #d4edda; color: #155724; }}
        .status-fail {{ background-color: #f8d7da; color: #721c24; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .chart-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 15px;
            color: #333;
        }}
        .modules-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .modules-table th,
        .modules-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .modules-table th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .grade-a {{ color: #28a745; font-weight: bold; }}
        .grade-b {{ color: #ffc107; font-weight: bold; }}
        .grade-c {{ color: #fd7e14; font-weight: bold; }}
        .grade-d {{ color: #dc3545; font-weight: bold; }}
        .grade-f {{ color: #dc3545; font-weight: bold; }}
        .recommendations {{
            background: #e7f3ff;
            border: 1px solid #b8daff;
            border-radius: 8px;
            padding: 20px;
            margin: 30px 0;
        }}
        .recommendations h3 {{
            color: #0066cc;
            margin-top: 0;
        }}
        .recommendations ul {{
            margin: 10px 0;
        }}
        .recommendations li {{
            margin: 8px 0;
            padding-left: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Code Quality Dashboard</h1>
            <p>PRS Backend - Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}</p>
            <div class="status-badge {'status-pass' if report.quality_gates_passed else 'status-fail'}">
                {'✅ Quality Gates PASSED' if report.quality_gates_passed else '❌ Quality Gates FAILED'}
            </div>
        </div>

        <!-- Key Metrics -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{report.total_files:,}</div>
                <div class="metric-label">Total Files</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.total_lines:,}</div>
                <div class="metric-label">Total Lines of Code</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.summary.get('average_lines_per_file', 0):.0f}</div>
                <div class="metric-label">Avg Lines per File</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(report.critical_files)}</div>
                <div class="metric-label">Critical Files</div>
            </div>
        </div>

        <!-- Quality Trend Chart -->
        <div class="chart-container">
            <div class="chart-title">📈 Quality Trend (Last 30 Days)</div>
            <canvas id="trendChart" width="400" height="200"></canvas>
        </div>

        <!-- Module Quality Chart -->
        <div class="chart-container">
            <div class="chart-title">🎯 Module Quality Grades</div>
            <canvas id="moduleChart" width="400" height="200"></canvas>
        </div>

        <!-- Modules Table -->
        <div class="chart-container">
            <div class="chart-title">📋 Module Details</div>
            <table class="modules-table">
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Files</th>
                        <th>Lines</th>
                        <th>Avg Lines/File</th>
                        <th>Quality Grade</th>
                        <th>Complexity</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_module_table_rows(report)}
                </tbody>
            </table>
        </div>

        <!-- Critical Files -->
        {self._generate_critical_files_section(report)}

        <!-- Recommendations -->
        <div class="recommendations">
            <h3>💡 Quality Improvement Recommendations</h3>
            <ul>
                {self._generate_recommendations_html(report)}
            </ul>
        </div>

        <!-- Footer -->
        <div style="text-align: center; margin-top: 40px; color: #666; font-size: 0.9em;">
            <p>Generated by PRS Quality Dashboard • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>

    <script>
        // Quality Trend Chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {trend_data},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'top',
                    }},
                    title: {{
                        display: true,
                        text: 'Code Quality Metrics Over Time'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        // Module Quality Chart
        const moduleCtx = document.getElementById('moduleChart').getContext('2d');
        new Chart(moduleCtx, {{
            type: 'doughnut',
            data: {module_data},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right',
                    }},
                    title: {{
                        display: true,
                        text: 'Module Quality Grade Distribution'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_trend_data(self, snapshots: List[QualitySnapshot]) -> str:
        """Generate trend chart data"""
        if not snapshots:
            return "{}"
        
        # Sort by timestamp
        snapshots.sort(key=lambda s: s.timestamp)
        
        dates = [s.timestamp[:10] for s in snapshots]  # YYYY-MM-DD
        total_lines = [s.total_lines for s in snapshots]
        avg_lines = [s.average_lines_per_file for s in snapshots]
        critical_files = [s.critical_files_count for s in snapshots]
        
        trend_data = {
            "labels": dates,
            "datasets": [
                {
                    "label": "Total Lines",
                    "data": total_lines,
                    "borderColor": "#007bff",
                    "backgroundColor": "rgba(0,123,255,0.1)",
                    "yAxisID": "y"
                },
                {
                    "label": "Avg Lines/File",
                    "data": avg_lines,
                    "borderColor": "#28a745",
                    "backgroundColor": "rgba(40,167,69,0.1)",
                    "yAxisID": "y1"
                },
                {
                    "label": "Critical Files",
                    "data": critical_files,
                    "borderColor": "#dc3545",
                    "backgroundColor": "rgba(220,53,69,0.1)",
                    "yAxisID": "y1"
                }
            ]
        }
        
        return json.dumps(trend_data)
    
    def _generate_module_data(self, report: QualityReport) -> str:
        """Generate module quality chart data"""
        grade_counts = {
            'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0
        }
        
        for module in report.modules:
            if module.quality_grade in grade_counts:
                grade_counts[module.quality_grade] += 1
        
        module_data = {
            "labels": list(grade_counts.keys()),
            "datasets": [{
                "data": list(grade_counts.values()),
                "backgroundColor": [
                    "#28a745",  # A - Green
                    "#ffc107",  # B - Yellow  
                    "#fd7e14",  # C - Orange
                    "#dc3545",  # D - Red
                    "#6f42c1"   # F - Purple
                ]
            }]
        }
        
        return json.dumps(module_data)
    
    def _generate_critical_files_data(self, report: QualityReport) -> str:
        """Generate critical files data"""
        return json.dumps([
            {
                "file": f.file_path,
                "lines": f.line_count,
                "complexity": f.complexity_score
            }
            for f in report.critical_files[:10]
        ])
    
    def _generate_module_table_rows(self, report: QualityReport) -> str:
        """Generate HTML table rows for modules"""
        rows = []
        for module in sorted(report.modules, key=lambda m: m.quality_grade):
            grade_class = f"grade-{module.quality_grade.lower()}"
            rows.append(f"""
                <tr>
                    <td>{module.module_name}</td>
                    <td>{module.total_files}</td>
                    <td>{module.total_lines:,}</td>
                    <td>{module.average_lines_per_file:.1f}</td>
                    <td><span class="{grade_class}">{module.quality_grade}</span></td>
                    <td>{module.complexity_score:.1f}</td>
                </tr>
            """)
        return "".join(rows)
    
    def _generate_critical_files_section(self, report: QualityReport) -> str:
        """Generate critical files section"""
        if not report.critical_files:
            return ""
        
        files_list = []
        for file in report.critical_files[:10]:
            files_list.append(f"""
                <tr>
                    <td>{file.file_path}</td>
                    <td>{file.line_count}</td>
                    <td>{file.complexity_score:.1f}</td>
                    <td>{file.maintainability_index:.1f}</td>
                </tr>
            """)
        
        return f"""
        <div class="chart-container">
            <div class="chart-title">🚨 Critical Files Requiring Attention</div>
            <table class="modules-table">
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Lines</th>
                        <th>Complexity</th>
                        <th>Maintainability</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(files_list)}
                </tbody>
            </table>
        </div>
        """
    
    def _generate_recommendations_html(self, report: QualityReport) -> str:
        """Generate recommendations as HTML list items"""
        return "".join([f"<li>{rec}</li>" for rec in report.recommendations])


def main():
    """Main entry point for quality dashboard"""
    parser = argparse.ArgumentParser(description="Generate quality reports and dashboards")
    parser.add_argument("--generate-dashboard", action="store_true", help="Generate HTML dashboard")
    parser.add_argument("--track-history", action="store_true", help="Save current metrics to history")
    parser.add_argument("--compare-modules", action="store_true", help="Generate module comparison report")
    parser.add_argument("--export", choices=['html', 'json'], help="Export format")
    parser.add_argument("--output", default="quality-dashboard.html", help="Output file path")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--days", type=int, default=30, help="Number of days for historical data")
    
    args = parser.parse_args()
    
    # Initialize generator
    project_root = Path(args.project_root).resolve()
    generator = QualityReportGenerator(str(project_root))
    
    if args.generate_dashboard:
        print("📊 Generating quality dashboard...")
        dashboard_path = generator.generate_html_dashboard(args.output)
        print(f"✅ Dashboard generated: {dashboard_path}")
        print(f"🌐 Open in browser: file://{Path(dashboard_path).absolute()}")
    
    elif args.track_history:
        print("📈 Tracking quality metrics...")
        analyzer = CodeComplexityAnalyzer(str(project_root))
        report = analyzer.analyze_project()
        snapshot_id = generator.db.save_snapshot(report)
        print(f"✅ Quality snapshot saved (ID: {snapshot_id})")
    
    elif args.compare_modules:
        print("🔍 Generating module comparison...")
        # TODO: Implement module comparison
        print("Module comparison not yet implemented")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
