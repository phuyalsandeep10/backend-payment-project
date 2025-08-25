"""
API Documentation Fix Management Command - Task 4.3.1

Django management command for analyzing and fixing API documentation completeness.
"""

from django.core.management.base import BaseCommand, CommandError
from core.performance.api_documentation_optimizer import (
    api_documentation_analyzer,
    analyze_api_documentation,
    generate_documentation_fixes,
    get_documentation_completeness_score
)
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    API documentation fix management command
    Task 4.3.1: API documentation optimization automation
    """
    
    help = 'Analyze and fix API documentation completeness issues'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            choices=['analyze', 'fixes', 'score', 'export'],
            default='analyze',
            help='Action to perform (default: analyze)'
        )
        
        parser.add_argument(
            '--export-file',
            type=str,
            help='File path to export analysis results'
        )
        
        parser.add_argument(
            '--show-templates',
            action='store_true',
            help='Show code templates for fixes'
        )
        
        parser.add_argument(
            '--category',
            choices=['endpoints', 'serializers', 'permissions', 'schemas', 'all'],
            default='all',
            help='Category of fixes to show (default: all)'
        )
        
        parser.add_argument(
            '--priority',
            choices=['critical', 'high', 'medium', 'low', 'all'],
            default='all',
            help='Priority level of issues to show (default: all)'
        )
    
    def handle(self, *args, **options):
        try:
            action = options['action']
            
            self.stdout.write(
                self.style.SUCCESS(f'📚 Starting API documentation analysis - Action: {action.upper()}')
            )
            
            if action == 'analyze':
                self._analyze_documentation(options)
            elif action == 'fixes':
                self._generate_fixes(options)
            elif action == 'score':
                self._show_completeness_score(options)
            elif action == 'export':
                self._export_analysis(options)
            
            self.stdout.write(
                self.style.SUCCESS('✅ API documentation analysis completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error in API documentation analysis: {e}")
            raise CommandError(f'API documentation analysis failed: {str(e)}')
    
    def _analyze_documentation(self, options):
        """Analyze API documentation completeness"""
        
        priority_filter = options['priority']
        
        self.stdout.write("Analyzing API documentation completeness...")
        
        analysis = analyze_api_documentation()
        
        self.stdout.write(f"\n📊 API Documentation Analysis Results")
        self.stdout.write('=' * 55)
        
        # Overall statistics
        total_endpoints = analysis['total_endpoints']
        documented_endpoints = analysis['documented_endpoints']
        completeness_score = analysis['completeness_score']
        
        self.stdout.write(f"Total API Endpoints: {total_endpoints}")
        self.stdout.write(f"Documented Endpoints: {documented_endpoints}")
        
        if total_endpoints > 0:
            doc_percentage = (documented_endpoints / total_endpoints) * 100
            
            if doc_percentage >= 80:
                doc_status = self.style.SUCCESS(f"{doc_percentage:.1f}%")
            elif doc_percentage >= 50:
                doc_status = self.style.WARNING(f"{doc_percentage:.1f}%")
            else:
                doc_status = self.style.ERROR(f"{doc_percentage:.1f}%")
            
            self.stdout.write(f"Documentation Coverage: {doc_status}")
        
        # Completeness score
        if completeness_score >= 80:
            score_status = self.style.SUCCESS(f"{completeness_score:.1f}%")
        elif completeness_score >= 50:
            score_status = self.style.WARNING(f"{completeness_score:.1f}%")
        else:
            score_status = self.style.ERROR(f"{completeness_score:.1f}%")
        
        self.stdout.write(f"Completeness Score: {score_status}")
        
        # Endpoint summary
        endpoint_summary = analysis['endpoint_summary']
        
        self.stdout.write(f"\n📈 Endpoint Summary:")
        
        # By HTTP method
        methods_data = endpoint_summary['by_method']
        if methods_data:
            self.stdout.write("  HTTP Methods:")
            for method, count in sorted(methods_data.items()):
                self.stdout.write(f"    {method}: {count}")
        
        # By documentation status
        doc_status_data = endpoint_summary['by_documentation_status']
        self.stdout.write("  Documentation Status:")
        self.stdout.write(f"    ✅ Fully Documented: {doc_status_data['documented']}")
        self.stdout.write(f"    ⚠️  Partially Documented: {doc_status_data['partially_documented']}")
        self.stdout.write(f"    ❌ Undocumented: {doc_status_data['undocumented']}")
        
        # Top-level paths
        top_paths = endpoint_summary['top_paths']
        if top_paths:
            self.stdout.write("  Top API Paths:")
            for path, count in top_paths[:5]:
                self.stdout.write(f"    {path}: {count} endpoints")
        
        # Documentation issues
        doc_issues = analysis['documentation_issues']
        if doc_issues:
            self.stdout.write(f"\n⚠️ Documentation Issues ({len(doc_issues)}):")
            
            for issue in doc_issues[:10]:  # Show first 10
                endpoint = issue['endpoint']
                methods = ", ".join(issue['methods'][:3])
                issues_list = issue['issues']
                
                self.stdout.write(f"  📍 {endpoint} ({methods}):")
                for issue_item in issues_list[:3]:  # Show first 3 issues
                    self.stdout.write(f"    • {issue_item}")
            
            if len(doc_issues) > 10:
                self.stdout.write(f"    ... and {len(doc_issues) - 10} more issues")
        
        # Schema issues
        schema_issues = analysis['schema_issues']
        if schema_issues:
            self.stdout.write(f"\n🔧 OpenAPI Schema Issues ({len(schema_issues)}):")
            
            for schema_issue in schema_issues[:5]:  # Show first 5
                if 'endpoint' in schema_issue:
                    self.stdout.write(f"  📍 {schema_issue['endpoint']}:")
                    for issue in schema_issue['issues']:
                        self.stdout.write(f"    • {issue}")
                else:
                    # General issues
                    for key, value in schema_issue.items():
                        self.stdout.write(f"  • {key}: {value}")
        
        # Missing documentation
        missing_docs = analysis['missing_documentation']
        if missing_docs:
            self.stdout.write(f"\n❌ Missing Documentation ({len(missing_docs)}):")
            
            for missing in missing_docs[:10]:  # Show first 10
                endpoint = missing['endpoint']
                methods = ", ".join(missing['methods'][:3])
                self.stdout.write(f"  📍 {endpoint} ({methods})")
            
            if len(missing_docs) > 10:
                self.stdout.write(f"    ... and {len(missing_docs) - 10} more undocumented endpoints")
        
        # Recommendations
        recommendations = analysis['recommendations']
        if recommendations:
            # Filter by priority
            if priority_filter != 'all':
                recommendations = [r for r in recommendations if r['priority'] == priority_filter]
            
            self.stdout.write(f"\n💡 Recommendations:")
            
            for rec in recommendations:
                priority = rec['priority']
                priority_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(priority, '⚪')
                
                self.stdout.write(f"  {priority_icon} {rec['title']} ({priority.upper()})")
                self.stdout.write(f"    {rec['description']}")
                self.stdout.write(f"    Action: {rec['action']}")
        
        # Next steps
        self.stdout.write(f"\n🚀 Next Steps:")
        if completeness_score < 50:
            self.stdout.write("  1. 🔴 URGENT: Add basic documentation to undocumented endpoints")
            self.stdout.write("  2. Focus on high-traffic API endpoints first")
            self.stdout.write("  3. Use --action=fixes to get specific code templates")
        elif completeness_score < 80:
            self.stdout.write("  1. Complete documentation for partially documented endpoints")
            self.stdout.write("  2. Add OpenAPI schema improvements")
            self.stdout.write("  3. Use --action=fixes for specific improvements")
        else:
            self.stdout.write("  1. ✅ Good documentation coverage!")
            self.stdout.write("  2. Focus on schema improvements and advanced features")
            self.stdout.write("  3. Regular maintenance and updates")
    
    def _generate_fixes(self, options):
        """Generate specific documentation fixes"""
        
        category = options['category']
        show_templates = options['show_templates']
        
        self.stdout.write("Generating documentation fixes...")
        
        fixes = generate_documentation_fixes()
        
        self.stdout.write(f"\n🔧 API Documentation Fixes")
        self.stdout.write('=' * 45)
        
        # Missing docstrings
        if category in ['endpoints', 'all'] and fixes['missing_docstrings']:
            self.stdout.write(f"\n📝 Missing Docstrings ({len(fixes['missing_docstrings'])}):")
            
            for fix in fixes['missing_docstrings'][:5]:  # Show first 5
                self.stdout.write(f"  📍 {fix['endpoint']} - {fix['view_class']}")
                
                if show_templates:
                    self.stdout.write("    Template:")
                    template_lines = fix['template'].strip().split('\n')
                    for line in template_lines[:10]:  # Show first 10 lines
                        self.stdout.write(f"    {line}")
                    if len(template_lines) > 10:
                        self.stdout.write("    ... (template truncated)")
                    self.stdout.write("")
        
        # Missing serializers
        if category in ['serializers', 'all'] and fixes['missing_serializers']:
            self.stdout.write(f"\n🔄 Missing Serializers ({len(fixes['missing_serializers'])}):")
            
            for fix in fixes['missing_serializers'][:5]:  # Show first 5
                self.stdout.write(f"  📍 {fix['endpoint']} - {fix['view_class']}")
                
                if show_templates:
                    self.stdout.write("    Template:")
                    template_lines = fix['template'].strip().split('\n')
                    for line in template_lines[:15]:  # Show first 15 lines
                        self.stdout.write(f"    {line}")
                    if len(template_lines) > 15:
                        self.stdout.write("    ... (template truncated)")
                    self.stdout.write("")
        
        # Schema improvements
        if category in ['schemas', 'all'] and fixes['schema_improvements']:
            self.stdout.write(f"\n📋 Schema Improvements ({len(fixes['schema_improvements'])}):")
            
            for fix in fixes['schema_improvements'][:3]:  # Show first 3
                self.stdout.write(f"  📍 {fix['endpoint']} - {fix['view_class']}")
                
                if show_templates:
                    self.stdout.write("    Template:")
                    template_lines = fix['template'].strip().split('\n')
                    for line in template_lines[:20]:  # Show first 20 lines
                        self.stdout.write(f"    {line}")
                    if len(template_lines) > 20:
                        self.stdout.write("    ... (template truncated)")
                    self.stdout.write("")
        
        # Permission additions
        if category in ['permissions', 'all'] and fixes['permission_additions']:
            self.stdout.write(f"\n🔒 Permission Additions ({len(fixes['permission_additions'])}):")
            
            for fix in fixes['permission_additions'][:5]:  # Show first 5
                self.stdout.write(f"  📍 {fix['endpoint']} - {fix['view_class']}")
                
                if show_templates:
                    self.stdout.write("    Template:")
                    template_lines = fix['template'].strip().split('\n')
                    for line in template_lines[:10]:  # Show first 10 lines
                        self.stdout.write(f"    {line}")
                    self.stdout.write("")
        
        # Implementation tips
        self.stdout.write(f"\n💡 Implementation Tips:")
        self.stdout.write("  1. Start with high-priority endpoints (most used APIs)")
        self.stdout.write("  2. Add docstrings first, then serializers")
        self.stdout.write("  3. Test OpenAPI schema generation after changes")
        self.stdout.write("  4. Use --show-templates to get full code templates")
        self.stdout.write("  5. Consider using drf-yasg for advanced schema features")
        
        # Total fixes summary
        total_fixes = (
            len(fixes['missing_docstrings']) +
            len(fixes['missing_serializers']) +
            len(fixes['schema_improvements']) +
            len(fixes['permission_additions'])
        )
        
        self.stdout.write(f"\n📊 Total Fixes Available: {total_fixes}")
    
    def _show_completeness_score(self, options):
        """Show just the completeness score"""
        
        self.stdout.write("Calculating documentation completeness score...")
        
        score = get_documentation_completeness_score()
        
        if score >= 90:
            score_status = self.style.SUCCESS(f"{score:.1f}%")
            rating = "EXCELLENT"
        elif score >= 80:
            score_status = self.style.SUCCESS(f"{score:.1f}%")
            rating = "GOOD"
        elif score >= 60:
            score_status = self.style.WARNING(f"{score:.1f}%")
            rating = "FAIR"
        elif score >= 40:
            score_status = self.style.WARNING(f"{score:.1f}%")
            rating = "POOR"
        else:
            score_status = self.style.ERROR(f"{score:.1f}%")
            rating = "CRITICAL"
        
        self.stdout.write(f"\n📊 API Documentation Completeness Score")
        self.stdout.write('=' * 50)
        self.stdout.write(f"Score: {score_status}")
        self.stdout.write(f"Rating: {rating}")
        
        # Score interpretation
        self.stdout.write(f"\n📖 Score Interpretation:")
        if score >= 80:
            self.stdout.write("  ✅ Your API documentation is in good shape!")
            self.stdout.write("  Focus on fine-tuning and advanced features.")
        elif score >= 60:
            self.stdout.write("  ⚠️ Decent documentation coverage.")
            self.stdout.write("  Consider improving completeness and quality.")
        else:
            self.stdout.write("  🔴 Documentation needs significant improvement.")
            self.stdout.write("  Start with basic docstrings and essential endpoints.")
    
    def _export_analysis(self, options):
        """Export detailed analysis to file"""
        
        export_file = options.get('export_file')
        if not export_file:
            from django.utils import timezone
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            export_file = f'api_documentation_analysis_{timestamp}.json'
        
        self.stdout.write(f"Exporting API documentation analysis to {export_file}...")
        
        try:
            analysis = analyze_api_documentation()
            fixes = generate_documentation_fixes()
            
            export_data = {
                'timestamp': timezone.now().isoformat(),
                'analysis': analysis,
                'fixes': fixes,
                'summary': {
                    'total_endpoints': analysis['total_endpoints'],
                    'completeness_score': analysis['completeness_score'],
                    'total_issues': len(analysis['documentation_issues']) + len(analysis['schema_issues']),
                    'total_fixes_available': (
                        len(fixes['missing_docstrings']) +
                        len(fixes['missing_serializers']) +
                        len(fixes['schema_improvements']) +
                        len(fixes['permission_additions'])
                    )
                }
            }
            
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.stdout.write(f"\n✅ Analysis exported to: {export_file}")
            
            # Show export summary
            summary = export_data['summary']
            self.stdout.write(f"\n📊 Export Summary:")
            self.stdout.write(f"  Total Endpoints: {summary['total_endpoints']}")
            self.stdout.write(f"  Completeness Score: {summary['completeness_score']:.1f}%")
            self.stdout.write(f"  Issues Found: {summary['total_issues']}")
            self.stdout.write(f"  Fixes Available: {summary['total_fixes_available']}")
            
        except Exception as e:
            raise CommandError(f"Failed to export analysis: {str(e)}")
