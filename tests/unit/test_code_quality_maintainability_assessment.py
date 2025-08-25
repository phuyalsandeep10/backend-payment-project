#!/usr/bin/env python3
"""
Code Quality and Maintainability Assessment for PRS System
Analyzes code organization, model relationships, serializers, and testing coverage
"""

import os
import sys
import json
import ast
import re
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

# Add Django settings
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

import django
django.setup()

from django.apps import apps
from django.db import models
from django.core.management import call_command
from django.test.utils import get_runner
from django.conf import settings
from rest_framework import serializers

class CodeQualityAssessment:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'code_organization': {},
            'model_relationships': {},
            'serializer_analysis': {},
            'testing_coverage': {},
            'maintainability_metrics': {},
            'recommendations': []
        }
        self.project_root = Path(__file__).parent
        
    def analyze_code_organization(self):
        """Analyze code organization and separation of concerns"""
        print("🔍 Analyzing code organization and separation of concerns...")
        
        organization_metrics = {
            'app_structure': {},
            'file_organization': {},
            'separation_of_concerns': {},
            'code_complexity': {}
        }
        
        # Analyze Django app structure
        for app_config in apps.get_app_configs():
            if app_config.name.startswith('core_config') or app_config.name in [
                'authentication', 'deals', 'clients', 'commission', 
                'permissions', 'organization', 'team', 'notifications',
                'Sales_dashboard', 'Verifier_dashboard', 'project'
            ]:
                app_path = Path(app_config.path)
                app_analysis = self._analyze_app_structure(app_path, app_config.name)
                organization_metrics['app_structure'][app_config.name] = app_analysis
        
        # Analyze file organization patterns
        organization_metrics['file_organization'] = self._analyze_file_organization()
        
        # Analyze separation of concerns
        organization_metrics['separation_of_concerns'] = self._analyze_separation_of_concerns()
        
        self.results['code_organization'] = organization_metrics
        
    def _analyze_app_structure(self, app_path, app_name):
        """Analyze individual Django app structure"""
        structure = {
            'files_present': [],
            'missing_standard_files': [],
            'custom_files': [],
            'complexity_score': 0,
            'lines_of_code': 0
        }
        
        standard_files = ['models.py', 'views.py', 'serializers.py', 'urls.py', 'admin.py', 'apps.py']
        
        if app_path.exists():
            for file_path in app_path.rglob('*.py'):
                if file_path.is_file() and not file_path.name.startswith('__'):
                    relative_path = file_path.relative_to(app_path)
                    structure['files_present'].append(str(relative_path))
                    
                    # Count lines of code
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = len([line for line in f if line.strip() and not line.strip().startswith('#')])
                            structure['lines_of_code'] += lines
                    except:
                        pass
            
            # Check for standard Django files
            for std_file in standard_files:
                if std_file not in [f for f in structure['files_present'] if f.endswith(std_file)]:
                    structure['missing_standard_files'].append(std_file)
            
            # Identify custom files (not standard Django patterns)
            for file_name in structure['files_present']:
                if not any(file_name.endswith(std) for std in standard_files + ['__init__.py', 'tests.py']):
                    if not file_name.startswith('test_') and not file_name.startswith('migrations/'):
                        structure['custom_files'].append(file_name)
        
        # Calculate complexity score based on number of files and LOC
        structure['complexity_score'] = len(structure['files_present']) + (structure['lines_of_code'] / 100)
        
        return structure
    
    def _analyze_file_organization(self):
        """Analyze overall file organization patterns"""
        patterns = {
            'naming_conventions': {},
            'directory_structure': {},
            'file_size_distribution': {}
        }
        
        # Analyze naming conventions
        file_names = []
        for py_file in self.project_root.rglob('*.py'):
            if 'migrations' not in str(py_file) and '__pycache__' not in str(py_file):
                file_names.append(py_file.name)
        
        patterns['naming_conventions'] = {
            'snake_case_files': len([f for f in file_names if '_' in f and f.islower()]),
            'camel_case_files': len([f for f in file_names if any(c.isupper() for c in f) and '_' not in f]),
            'total_files': len(file_names)
        }
        
        return patterns
    
    def _analyze_separation_of_concerns(self):
        """Analyze separation of concerns in the codebase"""
        concerns = {
            'business_logic_separation': {},
            'data_access_patterns': {},
            'presentation_layer_separation': {}
        }
        
        # Analyze views.py files for business logic separation
        view_files = list(self.project_root.rglob('views.py'))
        for view_file in view_files:
            try:
                with open(view_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                app_name = view_file.parent.name
                concerns['business_logic_separation'][app_name] = {
                    'has_business_logic': 'def ' in content and ('calculate' in content or 'process' in content),
                    'uses_serializers': 'serializer' in content.lower(),
                    'has_permissions': 'permission' in content.lower(),
                    'line_count': len(content.split('\n'))
                }
            except:
                pass
        
        return concerns

    def analyze_model_relationships(self):
        """Examine model relationships and cascade behaviors"""
        print("🔍 Analyzing model relationships and cascade behaviors...")
        
        relationship_analysis = {
            'foreign_key_relationships': {},
            'cascade_behaviors': {},
            'relationship_complexity': {},
            'potential_issues': []
        }
        
        for model in apps.get_models():
            if model._meta.app_label in ['authentication', 'deals', 'clients', 'commission', 
                                       'permissions', 'organization', 'team', 'notifications']:
                model_name = f"{model._meta.app_label}.{model.__name__}"
                
                # Analyze relationships
                relationships = self._analyze_model_relationships(model)
                relationship_analysis['foreign_key_relationships'][model_name] = relationships
                
                # Analyze cascade behaviors
                cascades = self._analyze_cascade_behaviors(model)
                relationship_analysis['cascade_behaviors'][model_name] = cascades
        
        # Calculate relationship complexity
        relationship_analysis['relationship_complexity'] = self._calculate_relationship_complexity(
            relationship_analysis['foreign_key_relationships']
        )
        
        self.results['model_relationships'] = relationship_analysis
    
    def _analyze_model_relationships(self, model):
        """Analyze relationships for a specific model"""
        relationships = {
            'foreign_keys': [],
            'many_to_many': [],
            'one_to_one': [],
            'reverse_relationships': []
        }
        
        # Analyze forward relationships
        for field in model._meta.get_fields():
            if isinstance(field, models.ForeignKey):
                relationships['foreign_keys'].append({
                    'field_name': field.name,
                    'related_model': f"{field.related_model._meta.app_label}.{field.related_model.__name__}",
                    'on_delete': str(field.on_delete) if hasattr(field, 'on_delete') else 'CASCADE'
                })
            elif isinstance(field, models.ManyToManyField):
                relationships['many_to_many'].append({
                    'field_name': field.name,
                    'related_model': f"{field.related_model._meta.app_label}.{field.related_model.__name__}"
                })
            elif isinstance(field, models.OneToOneField):
                relationships['one_to_one'].append({
                    'field_name': field.name,
                    'related_model': f"{field.related_model._meta.app_label}.{field.related_model.__name__}"
                })
        
        # Analyze reverse relationships
        for field in model._meta.get_fields():
            if hasattr(field, 'related_model') and field.related_model != model:
                if hasattr(field, 'get_accessor_name'):
                    relationships['reverse_relationships'].append({
                        'accessor_name': field.get_accessor_name(),
                        'related_model': f"{field.model._meta.app_label}.{field.model.__name__}",
                        'relationship_type': type(field).__name__
                    })
        
        return relationships
    
    def _analyze_cascade_behaviors(self, model):
        """Analyze cascade behaviors for model relationships"""
        cascades = {
            'cascade_deletes': [],
            'protect_relationships': [],
            'set_null_relationships': [],
            'potential_data_loss_risks': []
        }
        
        for field in model._meta.get_fields():
            if isinstance(field, models.ForeignKey):
                on_delete = getattr(field, 'on_delete', models.CASCADE)
                
                if on_delete == models.CASCADE:
                    cascades['cascade_deletes'].append(field.name)
                elif on_delete == models.PROTECT:
                    cascades['protect_relationships'].append(field.name)
                elif on_delete == models.SET_NULL:
                    cascades['set_null_relationships'].append(field.name)
                
                # Check for potential data loss risks
                if on_delete == models.CASCADE and not field.null:
                    cascades['potential_data_loss_risks'].append({
                        'field': field.name,
                        'risk': 'CASCADE delete without null option',
                        'related_model': f"{field.related_model._meta.app_label}.{field.related_model.__name__}"
                    })
        
        return cascades
    
    def _calculate_relationship_complexity(self, relationships):
        """Calculate overall relationship complexity metrics"""
        complexity = {
            'total_relationships': 0,
            'models_with_high_coupling': [],
            'circular_dependency_risk': []
        }
        
        relationship_counts = {}
        
        for model_name, rels in relationships.items():
            total_rels = (len(rels['foreign_keys']) + 
                         len(rels['many_to_many']) + 
                         len(rels['one_to_one']))
            
            relationship_counts[model_name] = total_rels
            complexity['total_relationships'] += total_rels
            
            # Flag models with high coupling (>5 relationships)
            if total_rels > 5:
                complexity['models_with_high_coupling'].append({
                    'model': model_name,
                    'relationship_count': total_rels
                })
        
        return complexity

    def validate_serializer_implementations(self):
        """Validate serializer implementations and data transformation"""
        print("🔍 Validating serializer implementations and data transformation...")
        
        serializer_analysis = {
            'serializer_files': {},
            'validation_patterns': {},
            'data_transformation': {},
            'best_practices': {}
        }
        
        # Find and analyze serializer files
        serializer_files = list(self.project_root.rglob('serializers.py'))
        
        for serializer_file in serializer_files:
            app_name = serializer_file.parent.name
            analysis = self._analyze_serializer_file(serializer_file)
            serializer_analysis['serializer_files'][app_name] = analysis
        
        # Analyze validation patterns
        serializer_analysis['validation_patterns'] = self._analyze_validation_patterns(serializer_files)
        
        # Analyze data transformation patterns
        serializer_analysis['data_transformation'] = self._analyze_data_transformation(serializer_files)
        
        self.results['serializer_analysis'] = serializer_analysis
    
    def _analyze_serializer_file(self, serializer_file):
        """Analyze individual serializer file"""
        analysis = {
            'serializer_classes': [],
            'validation_methods': [],
            'custom_fields': [],
            'line_count': 0,
            'complexity_indicators': {}
        }
        
        try:
            with open(serializer_file, 'r', encoding='utf-8') as f:
                content = f.read()
                analysis['line_count'] = len(content.split('\n'))
                
                # Parse AST to find serializer classes
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        # Check if it's a serializer class
                        for base in node.bases:
                            if isinstance(base, ast.Attribute) and base.attr.endswith('Serializer'):
                                analysis['serializer_classes'].append(node.name)
                        
                        # Find validation methods
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                if item.name.startswith('validate'):
                                    analysis['validation_methods'].append(item.name)
                
                # Look for complexity indicators
                analysis['complexity_indicators'] = {
                    'has_custom_validation': 'def validate' in content,
                    'uses_method_fields': 'SerializerMethodField' in content,
                    'has_nested_serializers': 'serializers.' in content and 'nested' in content.lower(),
                    'uses_write_methods': 'def create' in content or 'def update' in content
                }
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_validation_patterns(self, serializer_files):
        """Analyze validation patterns across serializers"""
        patterns = {
            'field_validation': {},
            'object_validation': {},
            'custom_validators': []
        }
        
        for serializer_file in serializer_files:
            try:
                with open(serializer_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Count validation patterns
                    field_validations = len(re.findall(r'def validate_\w+', content))
                    object_validations = len(re.findall(r'def validate\(', content))
                    
                    app_name = serializer_file.parent.name
                    patterns['field_validation'][app_name] = field_validations
                    patterns['object_validation'][app_name] = object_validations
                    
                    # Find custom validators
                    validator_matches = re.findall(r'validators=\[(.*?)\]', content)
                    if validator_matches:
                        patterns['custom_validators'].extend(validator_matches)
            except:
                pass
        
        return patterns
    
    def _analyze_data_transformation(self, serializer_files):
        """Analyze data transformation patterns"""
        transformation = {
            'method_fields': {},
            'custom_to_representation': {},
            'nested_serialization': {}
        }
        
        for serializer_file in serializer_files:
            try:
                with open(serializer_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    app_name = serializer_file.parent.name
                    
                    # Count method fields
                    method_fields = len(re.findall(r'SerializerMethodField', content))
                    transformation['method_fields'][app_name] = method_fields
                    
                    # Check for custom to_representation
                    has_custom_repr = 'def to_representation' in content
                    transformation['custom_to_representation'][app_name] = has_custom_repr
                    
                    # Check for nested serialization
                    nested_patterns = len(re.findall(r'serializers\.\w+Serializer', content))
                    transformation['nested_serialization'][app_name] = nested_patterns
                    
            except:
                pass
        
        return transformation

    def assess_testing_coverage(self):
        """Assess testing coverage and identify gaps"""
        print("🔍 Assessing testing coverage and identifying gaps...")
        
        testing_analysis = {
            'test_files': {},
            'coverage_gaps': {},
            'test_patterns': {},
            'recommendations': []
        }
        
        # Find all test files
        test_files = list(self.project_root.rglob('test_*.py')) + list(self.project_root.rglob('tests.py'))
        test_dirs = list(self.project_root.rglob('tests/'))
        
        # Analyze test files
        for test_file in test_files:
            if 'migrations' not in str(test_file) and '__pycache__' not in str(test_file):
                analysis = self._analyze_test_file(test_file)
                relative_path = str(test_file.relative_to(self.project_root))
                testing_analysis['test_files'][relative_path] = analysis
        
        # Analyze test directories
        for test_dir in test_dirs:
            if '__pycache__' not in str(test_dir):
                dir_analysis = self._analyze_test_directory(test_dir)
                relative_path = str(test_dir.relative_to(self.project_root))
                testing_analysis['test_files'][relative_path] = dir_analysis
        
        # Identify coverage gaps
        testing_analysis['coverage_gaps'] = self._identify_coverage_gaps()
        
        # Analyze test patterns
        testing_analysis['test_patterns'] = self._analyze_test_patterns(test_files)
        
        self.results['testing_coverage'] = testing_analysis
    
    def _analyze_test_file(self, test_file):
        """Analyze individual test file"""
        analysis = {
            'test_methods': [],
            'test_classes': [],
            'line_count': 0,
            'imports': [],
            'test_types': {}
        }
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                analysis['line_count'] = len(content.split('\n'))
                
                # Parse AST to find test classes and methods
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        if node.name.startswith('Test'):
                            analysis['test_classes'].append(node.name)
                            
                            # Find test methods in class
                            for item in node.body:
                                if isinstance(item, ast.FunctionDef) and item.name.startswith('test_'):
                                    analysis['test_methods'].append(f"{node.name}.{item.name}")
                    
                    elif isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                        analysis['test_methods'].append(node.name)
                    
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            analysis['imports'].append(alias.name)
                    
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            analysis['imports'].append(node.module)
                
                # Identify test types
                analysis['test_types'] = {
                    'unit_tests': 'TestCase' in content,
                    'integration_tests': 'APITestCase' in content or 'TransactionTestCase' in content,
                    'model_tests': 'models.' in content,
                    'view_tests': 'client.' in content or 'response' in content,
                    'serializer_tests': 'serializer' in content.lower()
                }
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_test_directory(self, test_dir):
        """Analyze test directory structure"""
        analysis = {
            'test_files_in_dir': [],
            'total_tests': 0,
            'directory_structure': {}
        }
        
        for test_file in test_dir.rglob('*.py'):
            if test_file.name != '__init__.py':
                file_analysis = self._analyze_test_file(test_file)
                analysis['test_files_in_dir'].append({
                    'file': test_file.name,
                    'test_count': len(file_analysis['test_methods'])
                })
                analysis['total_tests'] += len(file_analysis['test_methods'])
        
        return analysis
    
    def _identify_coverage_gaps(self):
        """Identify areas with insufficient test coverage"""
        gaps = {
            'untested_models': [],
            'untested_views': [],
            'untested_serializers': [],
            'missing_test_types': {}
        }
        
        # Get all models
        all_models = []
        for model in apps.get_models():
            if model._meta.app_label in ['authentication', 'deals', 'clients', 'commission']:
                all_models.append(f"{model._meta.app_label}.{model.__name__}")
        
        # Check which models have tests
        test_files = list(self.project_root.rglob('test_*.py'))
        tested_models = set()
        
        for test_file in test_files:
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for model_name in all_models:
                        if model_name.split('.')[-1] in content:
                            tested_models.add(model_name)
            except:
                pass
        
        gaps['untested_models'] = [model for model in all_models if model not in tested_models]
        
        return gaps
    
    def _analyze_test_patterns(self, test_files):
        """Analyze common test patterns and practices"""
        patterns = {
            'setup_patterns': {},
            'assertion_patterns': {},
            'mocking_usage': {},
            'fixture_usage': {}
        }
        
        for test_file in test_files:
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    app_name = test_file.parent.name
                    
                    # Analyze setup patterns
                    patterns['setup_patterns'][app_name] = {
                        'has_setup': 'def setUp' in content,
                        'has_teardown': 'def tearDown' in content,
                        'uses_fixtures': 'fixtures' in content
                    }
                    
                    # Analyze assertion patterns
                    assertion_count = len(re.findall(r'self\.assert\w+', content))
                    patterns['assertion_patterns'][app_name] = assertion_count
                    
                    # Analyze mocking usage
                    patterns['mocking_usage'][app_name] = {
                        'uses_mock': 'mock' in content.lower(),
                        'uses_patch': '@patch' in content or 'patch(' in content
                    }
                    
            except:
                pass
        
        return patterns

    def calculate_maintainability_metrics(self):
        """Calculate overall maintainability metrics"""
        print("🔍 Calculating maintainability metrics...")
        
        metrics = {
            'complexity_score': 0,
            'coupling_score': 0,
            'cohesion_score': 0,
            'test_coverage_score': 0,
            'documentation_score': 0,
            'overall_maintainability': 0
        }
        
        # Calculate complexity score based on code organization
        total_files = sum(len(app['files_present']) for app in self.results['code_organization']['app_structure'].values())
        total_loc = sum(app['lines_of_code'] for app in self.results['code_organization']['app_structure'].values())
        
        metrics['complexity_score'] = min(100, max(0, 100 - (total_loc / 1000)))  # Normalize to 0-100
        
        # Calculate coupling score based on relationships
        total_relationships = self.results['model_relationships']['relationship_complexity']['total_relationships']
        high_coupling_models = len(self.results['model_relationships']['relationship_complexity']['models_with_high_coupling'])
        
        metrics['coupling_score'] = max(0, 100 - (high_coupling_models * 10) - (total_relationships * 2))
        
        # Calculate test coverage score
        total_test_files = len(self.results['testing_coverage']['test_files'])
        total_app_files = len(self.results['code_organization']['app_structure'])
        
        if total_app_files > 0:
            metrics['test_coverage_score'] = min(100, (total_test_files / total_app_files) * 100)
        
        # Calculate overall maintainability (weighted average)
        weights = {
            'complexity_score': 0.3,
            'coupling_score': 0.25,
            'test_coverage_score': 0.25,
            'cohesion_score': 0.2
        }
        
        metrics['cohesion_score'] = 75  # Default reasonable score
        
        metrics['overall_maintainability'] = sum(
            metrics[metric] * weight for metric, weight in weights.items()
        )
        
        self.results['maintainability_metrics'] = metrics

    def generate_recommendations(self):
        """Generate actionable recommendations for improvement"""
        print("🔍 Generating recommendations for improvement...")
        
        recommendations = []
        
        # Code organization recommendations
        if self.results['code_organization']['app_structure']:
            high_complexity_apps = [
                app for app, data in self.results['code_organization']['app_structure'].items()
                if data['complexity_score'] > 20
            ]
            
            if high_complexity_apps:
                recommendations.append({
                    'category': 'Code Organization',
                    'priority': 'High',
                    'issue': f"High complexity in apps: {', '.join(high_complexity_apps)}",
                    'recommendation': 'Consider breaking down large apps into smaller, more focused modules',
                    'impact': 'Improved maintainability and easier testing'
                })
        
        # Model relationship recommendations
        high_coupling_models = self.results['model_relationships']['relationship_complexity']['models_with_high_coupling']
        if high_coupling_models:
            recommendations.append({
                'category': 'Model Relationships',
                'priority': 'Medium',
                'issue': f"High coupling detected in {len(high_coupling_models)} models",
                'recommendation': 'Review model relationships and consider using composition over inheritance',
                'impact': 'Reduced coupling and improved flexibility'
            })
        
        # Testing coverage recommendations
        untested_models = self.results['testing_coverage']['coverage_gaps']['untested_models']
        if untested_models:
            recommendations.append({
                'category': 'Testing Coverage',
                'priority': 'High',
                'issue': f"{len(untested_models)} models lack test coverage",
                'recommendation': 'Add comprehensive unit tests for all models, especially critical business logic',
                'impact': 'Improved reliability and easier refactoring'
            })
        
        # Serializer recommendations
        serializer_files = self.results['serializer_analysis']['serializer_files']
        complex_serializers = [
            app for app, data in serializer_files.items()
            if isinstance(data, dict) and data.get('line_count', 0) > 200
        ]
        
        if complex_serializers:
            recommendations.append({
                'category': 'Serializer Implementation',
                'priority': 'Medium',
                'issue': f"Complex serializers detected in: {', '.join(complex_serializers)}",
                'recommendation': 'Break down large serializers into smaller, focused ones',
                'impact': 'Improved readability and easier maintenance'
            })
        
        # Maintainability recommendations
        overall_score = self.results['maintainability_metrics']['overall_maintainability']
        if overall_score < 70:
            recommendations.append({
                'category': 'Overall Maintainability',
                'priority': 'High',
                'issue': f"Overall maintainability score is {overall_score:.1f}/100",
                'recommendation': 'Focus on improving test coverage, reducing complexity, and documenting code',
                'impact': 'Significantly improved long-term maintainability'
            })
        
        self.results['recommendations'] = recommendations

    def run_assessment(self):
        """Run the complete code quality and maintainability assessment"""
        print("🚀 Starting Code Quality and Maintainability Assessment...")
        print("=" * 60)
        
        try:
            # Run all analysis components
            self.analyze_code_organization()
            self.analyze_model_relationships()
            self.validate_serializer_implementations()
            self.assess_testing_coverage()
            self.calculate_maintainability_metrics()
            self.generate_recommendations()
            
            # Save results
            results_file = 'code_quality_maintainability_assessment_results.json'
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            print(f"\n✅ Assessment completed successfully!")
            print(f"📊 Results saved to: {results_file}")
            
            # Print summary
            self.print_summary()
            
            return True
            
        except Exception as e:
            print(f"❌ Assessment failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def print_summary(self):
        """Print assessment summary"""
        print("\n" + "=" * 60)
        print("📋 CODE QUALITY AND MAINTAINABILITY ASSESSMENT SUMMARY")
        print("=" * 60)
        
        # Code Organization Summary
        print("\n🏗️  CODE ORGANIZATION:")
        org_data = self.results['code_organization']['app_structure']
        total_apps = len(org_data)
        total_files = sum(len(app['files_present']) for app in org_data.values())
        total_loc = sum(app['lines_of_code'] for app in org_data.values())
        
        print(f"   • Total Django Apps: {total_apps}")
        print(f"   • Total Python Files: {total_files}")
        print(f"   • Total Lines of Code: {total_loc:,}")
        
        # Model Relationships Summary
        print("\n🔗 MODEL RELATIONSHIPS:")
        rel_data = self.results['model_relationships']['relationship_complexity']
        print(f"   • Total Relationships: {rel_data['total_relationships']}")
        print(f"   • High Coupling Models: {len(rel_data['models_with_high_coupling'])}")
        
        # Testing Coverage Summary
        print("\n🧪 TESTING COVERAGE:")
        test_data = self.results['testing_coverage']
        total_test_files = len(test_data['test_files'])
        untested_models = len(test_data['coverage_gaps']['untested_models'])
        
        print(f"   • Test Files Found: {total_test_files}")
        print(f"   • Untested Models: {untested_models}")
        
        # Maintainability Metrics Summary
        print("\n📊 MAINTAINABILITY METRICS:")
        metrics = self.results['maintainability_metrics']
        print(f"   • Overall Score: {metrics['overall_maintainability']:.1f}/100")
        print(f"   • Complexity Score: {metrics['complexity_score']:.1f}/100")
        print(f"   • Coupling Score: {metrics['coupling_score']:.1f}/100")
        print(f"   • Test Coverage Score: {metrics['test_coverage_score']:.1f}/100")
        
        # Recommendations Summary
        print(f"\n💡 RECOMMENDATIONS: {len(self.results['recommendations'])} issues identified")
        
        high_priority = [r for r in self.results['recommendations'] if r['priority'] == 'High']
        medium_priority = [r for r in self.results['recommendations'] if r['priority'] == 'Medium']
        
        if high_priority:
            print(f"   • High Priority Issues: {len(high_priority)}")
            for rec in high_priority[:3]:  # Show top 3
                print(f"     - {rec['issue']}")
        
        if medium_priority:
            print(f"   • Medium Priority Issues: {len(medium_priority)}")

if __name__ == "__main__":
    assessment = CodeQualityAssessment()
    success = assessment.run_assessment()
    
    if success:
        print("\n🎉 Code Quality and Maintainability Assessment completed successfully!")
        print("📁 Check the generated JSON file for detailed results.")
    else:
        print("\n❌ Assessment failed. Check the error messages above.")
        sys.exit(1)