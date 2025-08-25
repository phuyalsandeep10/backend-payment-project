"""
Comprehensive Security Testing Suite Runner - Task 6.1.1

Unified entry point for running all security tests including:
- Security test framework
- Vulnerability scanner  
- Penetration testing
- Security regression tests
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any
import subprocess


# Add current directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from security_test_framework import SecurityTestFramework, run_security_test_framework
    from vulnerability_scanner import VulnerabilityScanner, scan_project
    from penetration_testing import PenetrationTester, PenTestTarget, run_penetration_test
    from security_regression_framework import SecurityRegressionTester, run_security_regression_tests
except ImportError as e:
    print(f"⚠️  Import error: {e}")
    print("Please ensure all security testing modules are available")
    sys.exit(1)


class ComprehensiveSecurityTestSuite:
    """
    Comprehensive security testing suite
    Task 6.1.1: Complete automated security testing suite
    """
    
    def __init__(self, options: Dict[str, Any]):
        self.options = options
        self.results = {
            'framework_tests': None,
            'vulnerability_scan': None,
            'penetration_test': None,
            'regression_tests': None
        }
        self.overall_score = 0.0
        self.risk_level = 'UNKNOWN'
        
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run comprehensive security testing suite
        Task 6.1.1: Execute all security testing components
        """
        
        print("🛡️  COMPREHENSIVE SECURITY TESTING SUITE")
        print("=" * 70)
        print(f"Started at: {datetime.now()}")
        print(f"Project: {self.options.get('project_path', 'Current Directory')}")
        print(f"Target URL: {self.options.get('target_url', 'N/A')}")
        print("=" * 70)
        
        try:
            # 1. Security Test Framework
            if self.options.get('run_framework', True):
                print("\n🔬 PHASE 1: Security Test Framework")
                print("-" * 40)
                self.results['framework_tests'] = self._run_framework_tests()
            
            # 2. Vulnerability Scanning
            if self.options.get('run_scanner', True):
                print("\n🔍 PHASE 2: Vulnerability Scanner")
                print("-" * 40)
                self.results['vulnerability_scan'] = self._run_vulnerability_scan()
            
            # 3. Penetration Testing
            if self.options.get('run_pentest', False) and self.options.get('target_url'):
                print("\n🎯 PHASE 3: Penetration Testing")
                print("-" * 40)
                self.results['penetration_test'] = self._run_penetration_test()
            
            # 4. Security Regression Tests
            if self.options.get('run_regression', True):
                print("\n🔄 PHASE 4: Security Regression Tests")
                print("-" * 40)
                self.results['regression_tests'] = self._run_regression_tests()
            
            # 5. Generate comprehensive report
            print("\n📊 PHASE 5: Report Generation")
            print("-" * 40)
            comprehensive_report = self._generate_comprehensive_report()
            
            # 6. Display summary
            self._display_final_summary(comprehensive_report)
            
            return comprehensive_report
            
        except KeyboardInterrupt:
            print("\n⏹️  Security testing interrupted by user")
            return self._generate_partial_report()
            
        except Exception as e:
            print(f"\n❌ Security testing failed: {str(e)}")
            if self.options.get('verbose', False):
                import traceback
                traceback.print_exc()
            return self._generate_error_report(str(e))
    
    def _run_framework_tests(self) -> Dict[str, Any]:
        """Run security test framework"""
        try:
            print("Running automated security tests...")
            
            # Run framework tests
            framework_report = run_security_test_framework()
            
            if framework_report:
                summary = framework_report.get('executive_summary', {})
                print(f"✅ Framework tests completed:")
                print(f"   Security Score: {summary.get('overall_security_score', 0)}/100")
                print(f"   Tests: {summary.get('total_tests', 0)} run, {summary.get('tests_failed', 0)} failed")
                print(f"   Vulnerabilities: {summary.get('vulnerabilities_found', 0)}")
                
                return framework_report
            else:
                print("⚠️  Framework tests returned no results")
                return {'error': 'No results from framework tests'}
                
        except Exception as e:
            print(f"❌ Framework tests failed: {str(e)}")
            return {'error': str(e)}
    
    def _run_vulnerability_scan(self) -> Dict[str, Any]:
        """Run vulnerability scanner"""
        try:
            print("Running vulnerability scan...")
            
            project_path = self.options.get('project_path')
            if not project_path:
                project_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            # Run vulnerability scan
            scan_report = scan_project(project_path)
            
            if scan_report:
                summary = scan_report.get('summary', {})
                print(f"✅ Vulnerability scan completed:")
                print(f"   Risk Score: {summary.get('risk_score', 0)}/100")
                print(f"   Risk Level: {summary.get('risk_level', 'UNKNOWN')}")
                print(f"   Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                
                return scan_report
            else:
                print("⚠️  Vulnerability scan returned no results")
                return {'error': 'No results from vulnerability scan'}
                
        except Exception as e:
            print(f"❌ Vulnerability scan failed: {str(e)}")
            return {'error': str(e)}
    
    def _run_penetration_test(self) -> Dict[str, Any]:
        """Run penetration testing"""
        try:
            target_url = self.options.get('target_url')
            if not target_url:
                print("⏭️  Skipping penetration test (no target URL provided)")
                return {'skipped': 'No target URL provided'}
            
            print(f"Running penetration test against {target_url}...")
            
            # Run penetration test
            pentest_report = run_penetration_test(target_url)
            
            if pentest_report:
                summary = pentest_report.get('executive_summary', {})
                print(f"✅ Penetration test completed:")
                print(f"   Risk Score: {summary.get('risk_score', 0)}/100")
                print(f"   Risk Level: {summary.get('risk_level', 'UNKNOWN')}")
                print(f"   Vulnerable Findings: {summary.get('vulnerable_findings', 0)}")
                
                return pentest_report
            else:
                print("⚠️  Penetration test returned no results")
                return {'error': 'No results from penetration test'}
                
        except Exception as e:
            print(f"❌ Penetration test failed: {str(e)}")
            return {'error': str(e)}
    
    def _run_regression_tests(self) -> Dict[str, Any]:
        """Run security regression tests using the new regression framework"""
        try:
            print("Running security regression tests...")
            
            # Run comprehensive regression tests using the new framework
            regression_report = run_security_regression_tests()
            
            if regression_report:
                summary = regression_report.get('regression_summary', {})
                print(f"✅ Security regression tests completed:")
                print(f"   Tests: {summary.get('total_tests', 0)} run")
                print(f"   Passed: {summary.get('tests_passed', 0)}")
                print(f"   Failed: {summary.get('tests_failed', 0)}")
                print(f"   Regressions: {summary.get('regressions_detected', 0)}")
                print(f"   Errors: {summary.get('test_errors', 0)}")
                print(f"   Regression Rate: {summary.get('regression_rate', 0):.2f}%")
                
                # Also run legacy test scripts for compatibility
                legacy_results = self._run_legacy_security_tests()
                
                # Combine results
                combined_results = {
                    'regression_framework': regression_report,
                    'legacy_tests': legacy_results,
                    'combined_summary': {
                        'total_tests': summary.get('total_tests', 0) + legacy_results.get('tests_run', 0),
                        'regressions_detected': summary.get('regressions_detected', 0) + len(legacy_results.get('regressions_detected', [])),
                        'test_errors': summary.get('test_errors', 0) + legacy_results.get('tests_failed', 0)
                    }
                }
                
                return combined_results
            else:
                print("⚠️  Regression framework returned no results, falling back to legacy tests")
                return self._run_legacy_security_tests()
                
        except Exception as e:
            print(f"❌ Regression framework failed: {str(e)}, falling back to legacy tests")
            return self._run_legacy_security_tests()
    
    def _run_legacy_security_tests(self) -> Dict[str, Any]:
        """Run legacy security test scripts for compatibility"""
        try:
            regression_results = {
                'tests_run': 0,
                'tests_passed': 0,
                'tests_failed': 0,
                'regressions_detected': []
            }
            
            # Run existing security test scripts
            test_scripts = [
                'test_security_fixes_simple.py',
                'test_security_validation.py',
                'test_security_tasks_1_1_2_and_1_1_3.py'
            ]
            
            for script in test_scripts:
                script_path = os.path.join(current_dir, script)
                if os.path.exists(script_path):
                    try:
                        print(f"   Running legacy test {script}...")
                        result = subprocess.run(
                            [sys.executable, script_path],
                            capture_output=True,
                            text=True,
                            timeout=300  # 5 minute timeout
                        )
                        
                        regression_results['tests_run'] += 1
                        
                        if result.returncode == 0:
                            regression_results['tests_passed'] += 1
                        else:
                            regression_results['tests_failed'] += 1
                            regression_results['regressions_detected'].append({
                                'script': script,
                                'error': result.stderr[:200] if result.stderr else 'Unknown error',
                                'output': result.stdout[:200] if result.stdout else ''
                            })
                            
                    except subprocess.TimeoutExpired:
                        regression_results['tests_run'] += 1
                        regression_results['tests_failed'] += 1
                        regression_results['regressions_detected'].append({
                            'script': script,
                            'error': 'Test timeout (>5 minutes)',
                            'output': ''
                        })
                        
                    except Exception as e:
                        regression_results['tests_run'] += 1
                        regression_results['tests_failed'] += 1
                        regression_results['regressions_detected'].append({
                            'script': script,
                            'error': str(e),
                            'output': ''
                        })
            
            return regression_results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report combining all test results"""
        
        # Calculate overall metrics
        total_tests = 0
        total_failures = 0
        total_vulnerabilities = 0
        risk_scores = []
        
        # Framework tests
        if self.results['framework_tests'] and 'executive_summary' in self.results['framework_tests']:
            framework_summary = self.results['framework_tests']['executive_summary']
            total_tests += framework_summary.get('total_tests', 0)
            total_failures += framework_summary.get('tests_failed', 0)
            total_vulnerabilities += framework_summary.get('vulnerabilities_found', 0)
            risk_scores.append(framework_summary.get('overall_security_score', 0))
        
        # Vulnerability scan
        if self.results['vulnerability_scan'] and 'summary' in self.results['vulnerability_scan']:
            scan_summary = self.results['vulnerability_scan']['summary']
            total_vulnerabilities += scan_summary.get('total_vulnerabilities', 0)
            risk_scores.append(scan_summary.get('risk_score', 0))
        
        # Penetration test
        if self.results['penetration_test'] and 'executive_summary' in self.results['penetration_test']:
            pentest_summary = self.results['penetration_test']['executive_summary']
            total_tests += pentest_summary.get('total_tests', 0)
            total_failures += pentest_summary.get('vulnerable_findings', 0)
            risk_scores.append(pentest_summary.get('risk_score', 0))
        
        # Regression tests
        if self.results['regression_tests']:
            regression = self.results['regression_tests']
            
            # Handle both old format and new framework format
            if 'combined_summary' in regression:
                # New framework format
                combined_summary = regression['combined_summary']
                total_tests += combined_summary.get('total_tests', 0)
                total_failures += combined_summary.get('regressions_detected', 0) + combined_summary.get('test_errors', 0)
            elif 'regression_framework' in regression:
                # New framework only
                framework_summary = regression['regression_framework'].get('regression_summary', {})
                total_tests += framework_summary.get('total_tests', 0)
                total_failures += framework_summary.get('regressions_detected', 0) + framework_summary.get('test_errors', 0)
            else:
                # Legacy format
                total_tests += regression.get('tests_run', 0)
                total_failures += regression.get('tests_failed', 0)
        
        # Calculate overall risk assessment
        overall_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        overall_risk_level = self._assess_overall_risk_level(overall_risk_score, total_failures, total_vulnerabilities)
        
        comprehensive_report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'suite_version': '1.0.0',
                'project_path': self.options.get('project_path', 'Unknown'),
                'target_url': self.options.get('target_url', 'N/A'),
                'test_options': self.options
            },
            'executive_summary': {
                'overall_risk_score': round(overall_risk_score, 2),
                'overall_risk_level': overall_risk_level,
                'total_tests_run': total_tests,
                'total_test_failures': total_failures,
                'total_vulnerabilities_found': total_vulnerabilities,
                'tests_completed': {
                    'framework_tests': self.results['framework_tests'] is not None,
                    'vulnerability_scan': self.results['vulnerability_scan'] is not None,
                    'penetration_test': self.results['penetration_test'] is not None,
                    'regression_tests': self.results['regression_tests'] is not None
                }
            },
            'detailed_results': {
                'framework_tests': self.results['framework_tests'],
                'vulnerability_scan': self.results['vulnerability_scan'], 
                'penetration_test': self.results['penetration_test'],
                'regression_tests': self.results['regression_tests']
            },
            'security_recommendations': self._generate_consolidated_recommendations(),
            'compliance_assessment': self._assess_security_compliance()
        }
        
        # Save comprehensive report
        self._save_comprehensive_report(comprehensive_report)
        
        return comprehensive_report
    
    def _assess_overall_risk_level(self, risk_score: float, failures: int, vulnerabilities: int) -> str:
        """Assess overall risk level based on all test results"""
        
        # Critical risk conditions
        if vulnerabilities > 5 or failures > 10 or risk_score > 80:
            return 'CRITICAL'
        
        # High risk conditions  
        elif vulnerabilities > 2 or failures > 5 or risk_score > 60:
            return 'HIGH'
        
        # Medium risk conditions
        elif vulnerabilities > 0 or failures > 2 or risk_score > 40:
            return 'MEDIUM'
        
        # Low risk conditions
        elif failures > 0 or risk_score > 20:
            return 'LOW'
        
        else:
            return 'MINIMAL'
    
    def _generate_consolidated_recommendations(self) -> List[Dict[str, Any]]:
        """Generate consolidated security recommendations from all test results"""
        
        recommendations = []
        
        # Framework recommendations
        if (self.results['framework_tests'] and 
            'recommendations' in self.results['framework_tests']):
            for rec in self.results['framework_tests']['recommendations']:
                recommendations.append({
                    'source': 'framework_tests',
                    'priority': 'high',
                    'category': rec.get('category', 'general'),
                    'recommendation': rec.get('recommendation', ''),
                    'details': rec.get('details', [])
                })
        
        # Vulnerability scan recommendations
        if (self.results['vulnerability_scan'] and 
            'recommendations' in self.results['vulnerability_scan']):
            for rec in self.results['vulnerability_scan']['recommendations']:
                recommendations.append({
                    'source': 'vulnerability_scan',
                    'priority': rec.get('priority', 'medium'),
                    'category': rec.get('category', 'general'),
                    'recommendation': rec.get('title', ''),
                    'details': rec.get('actions', [])
                })
        
        # Penetration test recommendations
        if (self.results['penetration_test'] and 
            'recommendations' in self.results['penetration_test']):
            for rec in self.results['penetration_test']['recommendations']:
                recommendations.append({
                    'source': 'penetration_test',
                    'priority': rec.get('priority', 'high'),
                    'category': rec.get('category', 'general'),
                    'recommendation': rec.get('title', ''),
                    'details': rec.get('actions', [])
                })
        
        # Consolidate and prioritize
        return self._prioritize_recommendations(recommendations)
    
    def _prioritize_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize and deduplicate recommendations"""
        
        # Priority weights
        priority_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        # Sort by priority and deduplicate similar recommendations
        sorted_recs = sorted(
            recommendations, 
            key=lambda x: priority_weights.get(x.get('priority', 'low'), 0),
            reverse=True
        )
        
        # Take top 10 most critical recommendations
        return sorted_recs[:10]
    
    def _assess_security_compliance(self) -> Dict[str, Any]:
        """Assess security compliance based on test results"""
        
        compliance_score = 100
        compliance_issues = []
        
        # Check for critical vulnerabilities
        total_critical = 0
        if self.results['framework_tests']:
            framework_critical = len([
                r for r in self.results['framework_tests'].get('detailed_results', [])
                if r.get('severity') == 'critical' and r.get('status') == 'failed'
            ])
            total_critical += framework_critical
        
        if self.results['vulnerability_scan']:
            scan_critical = self.results['vulnerability_scan'].get('summary', {}).get(
                'vulnerabilities_by_severity', {}
            ).get('critical', 0)
            total_critical += scan_critical
        
        if total_critical > 0:
            compliance_score -= min(total_critical * 20, 80)  # Max 80 point deduction
            compliance_issues.append(f'{total_critical} critical vulnerabilities found')
        
        # Check for high-severity issues
        total_high = 0
        if self.results['framework_tests']:
            framework_high = len([
                r for r in self.results['framework_tests'].get('detailed_results', [])
                if r.get('severity') == 'high' and r.get('status') == 'failed'
            ])
            total_high += framework_high
        
        if self.results['vulnerability_scan']:
            scan_high = self.results['vulnerability_scan'].get('summary', {}).get(
                'vulnerabilities_by_severity', {}
            ).get('high', 0)
            total_high += scan_high
        
        if total_high > 2:  # Allow up to 2 high-severity issues
            compliance_score -= min((total_high - 2) * 10, 30)  # Max 30 point deduction
            compliance_issues.append(f'{total_high} high-severity vulnerabilities found')
        
        # Determine compliance level
        if compliance_score >= 95:
            compliance_level = 'EXCELLENT'
        elif compliance_score >= 85:
            compliance_level = 'GOOD'
        elif compliance_score >= 70:
            compliance_level = 'FAIR'
        elif compliance_score >= 50:
            compliance_level = 'POOR'
        else:
            compliance_level = 'FAILING'
        
        return {
            'compliance_score': max(compliance_score, 0),
            'compliance_level': compliance_level,
            'compliance_issues': compliance_issues,
            'recommendations': [
                'Address all critical vulnerabilities immediately',
                'Implement security testing in CI/CD pipeline',
                'Conduct regular security assessments',
                'Maintain security documentation and procedures'
            ]
        }
    
    def _display_final_summary(self, report: Dict[str, Any]):
        """Display final comprehensive summary"""
        
        print("\n" + "=" * 70)
        print("🛡️  COMPREHENSIVE SECURITY TESTING SUMMARY")
        print("=" * 70)
        
        summary = report['executive_summary']
        compliance = report['compliance_assessment']
        
        print(f"Overall Risk Score: {summary['overall_risk_score']}/100")
        print(f"Overall Risk Level: {summary['overall_risk_level']}")
        print(f"Compliance Score: {compliance['compliance_score']}/100 ({compliance['compliance_level']})")
        
        print(f"\n📊 Test Results:")
        print(f"   Total Tests: {summary['total_tests_run']}")
        print(f"   Test Failures: {summary['total_test_failures']}")
        print(f"   Vulnerabilities Found: {summary['total_vulnerabilities_found']}")
        
        print(f"\n🧪 Test Components:")
        tests_completed = summary['tests_completed']
        for test_name, completed in tests_completed.items():
            status = "✅" if completed else "⏭️"
            print(f"   {status} {test_name.replace('_', ' ').title()}")
        
        if report.get('security_recommendations'):
            print(f"\n📋 Priority Security Actions:")
            for i, rec in enumerate(report['security_recommendations'][:5], 1):
                priority_symbol = {'critical': '🔴', 'high': '🟠', 'medium': '🟡'}.get(
                    rec.get('priority', 'medium'), '🟡'
                )
                print(f"   {i}. {priority_symbol} {rec.get('recommendation', 'No recommendation')}")
        
        if compliance['compliance_issues']:
            print(f"\n⚠️  Compliance Issues:")
            for issue in compliance['compliance_issues']:
                print(f"   • {issue}")
    
    def _save_comprehensive_report(self, report: Dict[str, Any]):
        """Save comprehensive security report to file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"comprehensive_security_report_{timestamp}.json"
        filepath = os.path.join(current_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n💾 Comprehensive security report saved to: {filepath}")
            
            # Also create a summary text file
            summary_filename = f"security_summary_{timestamp}.txt"
            summary_filepath = os.path.join(current_dir, summary_filename)
            
            with open(summary_filepath, 'w') as f:
                f.write("COMPREHENSIVE SECURITY TESTING SUMMARY\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {report['report_metadata']['generated_at']}\n")
                f.write(f"Overall Risk Score: {report['executive_summary']['overall_risk_score']}/100\n")
                f.write(f"Overall Risk Level: {report['executive_summary']['overall_risk_level']}\n")
                f.write(f"Compliance Score: {report['compliance_assessment']['compliance_score']}/100\n")
                f.write(f"Total Tests: {report['executive_summary']['total_tests_run']}\n")
                f.write(f"Test Failures: {report['executive_summary']['total_test_failures']}\n")
                f.write(f"Vulnerabilities: {report['executive_summary']['total_vulnerabilities_found']}\n")
                
                if report.get('security_recommendations'):
                    f.write(f"\nPriority Recommendations:\n")
                    for i, rec in enumerate(report['security_recommendations'][:10], 1):
                        f.write(f"{i}. {rec.get('recommendation', 'No recommendation')}\n")
            
            print(f"📄 Security summary saved to: {summary_filepath}")
            
        except Exception as e:
            print(f"⚠️  Could not save comprehensive report: {e}")
    
    def _generate_partial_report(self) -> Dict[str, Any]:
        """Generate partial report when tests are interrupted"""
        return {
            'status': 'interrupted',
            'completed_tests': {k: v is not None for k, v in self.results.items()},
            'partial_results': self.results,
            'message': 'Security testing was interrupted before completion'
        }
    
    def _generate_error_report(self, error_message: str) -> Dict[str, Any]:
        """Generate error report when tests fail"""
        return {
            'status': 'error',
            'error_message': error_message,
            'partial_results': self.results,
            'message': 'Security testing failed due to an error'
        }


def main():
    """Main function to run comprehensive security testing suite"""
    
    parser = argparse.ArgumentParser(description='Comprehensive Security Testing Suite')
    
    parser.add_argument(
        '--project-path', 
        type=str,
        default=None,
        help='Path to project root for vulnerability scanning'
    )
    
    parser.add_argument(
        '--target-url', 
        type=str,
        default=None,
        help='Target URL for penetration testing'
    )
    
    parser.add_argument(
        '--framework', 
        action='store_true',
        default=True,
        help='Run security test framework (default: True)'
    )
    
    parser.add_argument(
        '--scanner', 
        action='store_true',
        default=True,
        help='Run vulnerability scanner (default: True)'
    )
    
    parser.add_argument(
        '--pentest', 
        action='store_true',
        default=False,
        help='Run penetration testing (requires --target-url)'
    )
    
    parser.add_argument(
        '--regression', 
        action='store_true',
        default=True,
        help='Run security regression tests (default: True)'
    )
    
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--output', 
        type=str,
        help='Output file path for comprehensive report'
    )
    
    args = parser.parse_args()
    
    # Prepare options
    options = {
        'project_path': args.project_path,
        'target_url': args.target_url,
        'run_framework': args.framework,
        'run_scanner': args.scanner,
        'run_pentest': args.pentest,
        'run_regression': args.regression,
        'verbose': args.verbose,
        'output': args.output
    }
    
    # Validate options
    if args.pentest and not args.target_url:
        print("❌ Error: --pentest requires --target-url")
        sys.exit(1)
    
    # Create and run test suite
    try:
        test_suite = ComprehensiveSecurityTestSuite(options)
        report = test_suite.run_all_tests()
        
        # Determine exit code based on results
        if report.get('status') == 'error':
            sys.exit(1)
        elif report.get('executive_summary', {}).get('overall_risk_level') in ['CRITICAL', 'HIGH']:
            print(f"\n⚠️  Exiting with error code due to {report['executive_summary']['overall_risk_level']} risk level")
            sys.exit(1)
        else:
            print(f"\n✅ Security testing completed successfully")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Security testing interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Security testing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
