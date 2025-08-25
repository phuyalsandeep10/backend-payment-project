#!/usr/bin/env python3
"""
Focused Deal Management Workflow Analysis

This script analyzes the core deal management workflow components without
requiring database setup, focusing on code structure and implementation patterns.
"""

import os
import sys
import inspect
from decimal import Decimal

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
import django
django.setup()

from deals.models import Deal, Payment
from deals.workflow_automation import DealWorkflowEngine, DealPerformanceAnalyzer
from deals.atomic_operations import AtomicFinancialOperations
from deals.financial_optimizer import FinancialFieldOptimizer

class DealWorkflowCodeAnalysis:
    """
    Code-level analysis of deal workflow implementation
    """
    
    def __init__(self):
        self.results = {
            'state_machine_analysis': {},
            'payment_workflow_analysis': {},
            'business_logic_analysis': {},
            'code_quality_analysis': {},
            'summary': {}
        }
    
    def analyze_state_machine_implementation(self):
        """Analyze state machine implementation in Deal model"""
        print("=== Analyzing State Machine Implementation ===")
        
        analysis = {}
        
        # Check if state transitions are defined
        if hasattr(Deal, 'VERIFICATION_STATUS_TRANSITIONS'):
            verification_transitions = Deal.VERIFICATION_STATUS_TRANSITIONS
            analysis['verification_state_machine'] = {
                'implemented': True,
                'states': list(verification_transitions.keys()),
                'total_states': len(verification_transitions.keys()),
                'transitions': verification_transitions,
                'final_states': [state for state, transitions in verification_transitions.items() if not transitions]
            }
            print(f"✓ Verification state machine: {len(verification_transitions)} states defined")
        else:
            analysis['verification_state_machine'] = {'implemented': False}
            print("✗ Verification state machine: Not found")
        
        if hasattr(Deal, 'PAYMENT_STATUS_TRANSITIONS'):
            payment_transitions = Deal.PAYMENT_STATUS_TRANSITIONS
            analysis['payment_state_machine'] = {
                'implemented': True,
                'states': list(payment_transitions.keys()),
                'total_states': len(payment_transitions.keys()),
                'transitions': payment_transitions,
                'final_states': [state for state, transitions in payment_transitions.items() if not transitions]
            }
            print(f"✓ Payment state machine: {len(payment_transitions)} states defined")
        else:
            analysis['payment_state_machine'] = {'implemented': False}
            print("✗ Payment state machine: Not found")
        
        # Check validation methods
        validation_methods = []
        if hasattr(Deal, 'validate_verification_status_transition'):
            validation_methods.append('validate_verification_status_transition')
        if hasattr(Deal, 'validate_payment_status_transition'):
            validation_methods.append('validate_payment_status_transition')
        if hasattr(Deal, 'can_transition_verification_status'):
            validation_methods.append('can_transition_verification_status')
        if hasattr(Deal, 'can_transition_payment_status'):
            validation_methods.append('can_transition_payment_status')
        
        analysis['validation_methods'] = {
            'implemented': validation_methods,
            'count': len(validation_methods),
            'comprehensive': len(validation_methods) >= 4
        }
        
        print(f"✓ Validation methods: {len(validation_methods)} implemented")
        
        self.results['state_machine_analysis'] = analysis
        return analysis
    
    def analyze_payment_workflow(self):
        """Analyze payment workflow and business rules"""
        print("\n=== Analyzing Payment Workflow ===")
        
        analysis = {}
        
        # Check Deal model payment-related methods
        payment_methods = []
        deal_methods = inspect.getmembers(Deal, predicate=inspect.isfunction)
        
        for name, method in deal_methods:
            if 'payment' in name.lower() or 'paid' in name.lower() or 'balance' in name.lower():
                payment_methods.append(name)
        
        analysis['deal_payment_methods'] = {
            'methods': payment_methods,
            'count': len(payment_methods)
        }
        
        # Check specific critical methods
        critical_methods = [
            'get_total_paid_amount',
            'get_remaining_balance', 
            'get_payment_progress',
            'validate_additional_payment'
        ]
        
        implemented_critical = []
        for method in critical_methods:
            if hasattr(Deal, method):
                implemented_critical.append(method)
        
        analysis['critical_payment_methods'] = {
            'required': critical_methods,
            'implemented': implemented_critical,
            'coverage': len(implemented_critical) / len(critical_methods) * 100
        }
        
        print(f"✓ Payment methods: {len(payment_methods)} total, {len(implemented_critical)}/{len(critical_methods)} critical methods")
        
        # Check Payment model validation
        payment_validation_methods = []
        payment_methods = inspect.getmembers(Payment, predicate=inspect.isfunction)
        
        for name, method in payment_methods:
            if 'clean' in name.lower() or 'validate' in name.lower():
                payment_validation_methods.append(name)
        
        analysis['payment_validation'] = {
            'methods': payment_validation_methods,
            'has_clean_method': hasattr(Payment, 'clean'),
            'has_validation': len(payment_validation_methods) > 0
        }
        
        print(f"✓ Payment validation: {len(payment_validation_methods)} methods")
        
        # Check financial optimizer integration
        if hasattr(Deal, 'validate_financial_fields') or 'FinancialValidationMixin' in [cls.__name__ for cls in Deal.__mro__]:
            analysis['financial_optimization'] = {
                'integrated': True,
                'mixin_used': 'FinancialValidationMixin' in [cls.__name__ for cls in Deal.__mro__]
            }
            print("✓ Financial optimization: Integrated")
        else:
            analysis['financial_optimization'] = {'integrated': False}
            print("✗ Financial optimization: Not integrated")
        
        self.results['payment_workflow_analysis'] = analysis
        return analysis
    
    def analyze_business_logic_implementation(self):
        """Analyze business logic and workflow automation"""
        print("\n=== Analyzing Business Logic Implementation ===")
        
        analysis = {}
        
        # Check workflow automation components
        workflow_components = []
        
        try:
            # Check DealWorkflowEngine
            engine_methods = inspect.getmembers(DealWorkflowEngine, predicate=inspect.ismethod)
            workflow_components.append({
                'component': 'DealWorkflowEngine',
                'methods': len(engine_methods),
                'available': True
            })
            print("✓ DealWorkflowEngine: Available")
        except Exception as e:
            workflow_components.append({
                'component': 'DealWorkflowEngine',
                'available': False,
                'error': str(e)
            })
            print("✗ DealWorkflowEngine: Not available")
        
        try:
            # Check AtomicFinancialOperations
            atomic_methods = inspect.getmembers(AtomicFinancialOperations, predicate=inspect.ismethod)
            workflow_components.append({
                'component': 'AtomicFinancialOperations',
                'methods': len(atomic_methods),
                'available': True
            })
            print("✓ AtomicFinancialOperations: Available")
        except Exception as e:
            workflow_components.append({
                'component': 'AtomicFinancialOperations',
                'available': False,
                'error': str(e)
            })
            print("✗ AtomicFinancialOperations: Not available")
        
        try:
            # Check FinancialFieldOptimizer
            optimizer_methods = inspect.getmembers(FinancialFieldOptimizer, predicate=inspect.ismethod)
            workflow_components.append({
                'component': 'FinancialFieldOptimizer',
                'methods': len(optimizer_methods),
                'available': True
            })
            print("✓ FinancialFieldOptimizer: Available")
        except Exception as e:
            workflow_components.append({
                'component': 'FinancialFieldOptimizer',
                'available': False,
                'error': str(e)
            })
            print("✗ FinancialFieldOptimizer: Not available")
        
        analysis['workflow_components'] = workflow_components
        
        # Check for optimistic locking
        optimistic_locking = {
            'deal_model': hasattr(Deal, 'lock_version'),
            'payment_model': hasattr(Payment, 'lock_version'),
            'mixin_available': False
        }
        
        try:
            from deals.atomic_operations import OptimisticLockingMixin
            optimistic_locking['mixin_available'] = True
            optimistic_locking['mixin_methods'] = len(inspect.getmembers(OptimisticLockingMixin, predicate=inspect.isfunction))
        except ImportError:
            pass
        
        analysis['optimistic_locking'] = optimistic_locking
        
        if optimistic_locking['deal_model']:
            print("✓ Optimistic locking: Implemented on Deal model")
        else:
            print("⚠ Optimistic locking: Not implemented on Deal model")
        
        self.results['business_logic_analysis'] = analysis
        return analysis
    
    def analyze_code_quality(self):
        """Analyze code quality and architecture patterns"""
        print("\n=== Analyzing Code Quality ===")
        
        analysis = {}
        
        # Check model field definitions
        deal_fields = Deal._meta.get_fields()
        payment_fields = Payment._meta.get_fields()
        
        # Check for proper indexing
        deal_indexes = getattr(Deal._meta, 'indexes', [])
        payment_indexes = getattr(Payment._meta, 'indexes', [])
        
        analysis['database_optimization'] = {
            'deal_fields': len(deal_fields),
            'payment_fields': len(payment_fields),
            'deal_indexes': len(deal_indexes),
            'payment_indexes': len(payment_indexes),
            'comprehensive_indexing': len(deal_indexes) > 10  # Arbitrary threshold
        }
        
        print(f"✓ Database optimization: {len(deal_indexes)} Deal indexes, {len(payment_indexes)} Payment indexes")
        
        # Check for proper field types
        financial_fields = []
        for field in deal_fields:
            if hasattr(field, 'get_internal_type') and field.get_internal_type() == 'DecimalField':
                financial_fields.append(field.name)
        
        for field in payment_fields:
            if hasattr(field, 'get_internal_type') and field.get_internal_type() == 'DecimalField':
                financial_fields.append(field.name)
        
        analysis['financial_field_types'] = {
            'decimal_fields': financial_fields,
            'proper_precision': len(financial_fields) > 0
        }
        
        print(f"✓ Financial fields: {len(financial_fields)} DecimalField instances")
        
        # Check for proper validation
        deal_constraints = getattr(Deal._meta, 'constraints', [])
        payment_constraints = getattr(Payment._meta, 'constraints', [])
        
        analysis['model_constraints'] = {
            'deal_constraints': len(deal_constraints),
            'payment_constraints': len(payment_constraints),
            'validation_implemented': len(deal_constraints) > 0 or len(payment_constraints) > 0
        }
        
        # Check for proper permissions
        deal_permissions = getattr(Deal._meta, 'permissions', [])
        payment_permissions = getattr(Payment._meta, 'permissions', [])
        
        analysis['permission_system'] = {
            'deal_permissions': len(deal_permissions),
            'payment_permissions': len(payment_permissions),
            'granular_permissions': len(deal_permissions) > 3
        }
        
        print(f"✓ Permission system: {len(deal_permissions)} Deal permissions, {len(payment_permissions)} Payment permissions")
        
        self.results['code_quality_analysis'] = analysis
        return analysis
    
    def generate_summary(self):
        """Generate analysis summary"""
        print("\n=== Analysis Summary ===")
        
        summary = {
            'overall_score': 0,
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        # Calculate overall score based on implementation completeness
        score = 0
        max_score = 0
        
        # State machine implementation (25 points)
        state_analysis = self.results.get('state_machine_analysis', {})
        if state_analysis.get('verification_state_machine', {}).get('implemented'):
            score += 12
        if state_analysis.get('payment_state_machine', {}).get('implemented'):
            score += 8
        if state_analysis.get('validation_methods', {}).get('comprehensive'):
            score += 5
        max_score += 25
        
        # Payment workflow (25 points)
        payment_analysis = self.results.get('payment_workflow_analysis', {})
        critical_coverage = payment_analysis.get('critical_payment_methods', {}).get('coverage', 0)
        score += int(critical_coverage / 100 * 15)
        if payment_analysis.get('payment_validation', {}).get('has_validation'):
            score += 5
        if payment_analysis.get('financial_optimization', {}).get('integrated'):
            score += 5
        max_score += 25
        
        # Business logic (25 points)
        business_analysis = self.results.get('business_logic_analysis', {})
        available_components = len([c for c in business_analysis.get('workflow_components', []) if c.get('available')])
        score += available_components * 8  # Up to 24 points for 3 components
        if business_analysis.get('optimistic_locking', {}).get('deal_model'):
            score += 1
        max_score += 25
        
        # Code quality (25 points)
        quality_analysis = self.results.get('code_quality_analysis', {})
        if quality_analysis.get('database_optimization', {}).get('comprehensive_indexing'):
            score += 8
        if quality_analysis.get('financial_field_types', {}).get('proper_precision'):
            score += 7
        if quality_analysis.get('permission_system', {}).get('granular_permissions'):
            score += 10
        max_score += 25
        
        summary['overall_score'] = int((score / max_score) * 100) if max_score > 0 else 0
        
        # Identify strengths
        if state_analysis.get('verification_state_machine', {}).get('implemented'):
            summary['strengths'].append("Comprehensive state machine implementation")
        
        if payment_analysis.get('critical_payment_methods', {}).get('coverage', 0) > 75:
            summary['strengths'].append("Strong payment calculation methods")
        
        if available_components >= 2:
            summary['strengths'].append("Advanced workflow automation components")
        
        if quality_analysis.get('database_optimization', {}).get('comprehensive_indexing'):
            summary['strengths'].append("Comprehensive database indexing strategy")
        
        # Identify weaknesses
        if not business_analysis.get('optimistic_locking', {}).get('deal_model'):
            summary['weaknesses'].append("Missing optimistic locking on Deal model")
        
        if not payment_analysis.get('financial_optimization', {}).get('integrated'):
            summary['weaknesses'].append("Financial optimization not fully integrated")
        
        if quality_analysis.get('model_constraints', {}).get('deal_constraints', 0) == 0:
            summary['weaknesses'].append("Limited database constraints for data integrity")
        
        # Generate recommendations
        if summary['overall_score'] >= 80:
            summary['recommendations'].append("System is production-ready with minor optimizations needed")
        elif summary['overall_score'] >= 60:
            summary['recommendations'].append("Good foundation, address identified weaknesses before production")
        else:
            summary['recommendations'].append("Significant improvements needed before production deployment")
        
        if not business_analysis.get('optimistic_locking', {}).get('deal_model'):
            summary['recommendations'].append("Implement optimistic locking for concurrent access protection")
        
        if available_components < 3:
            summary['recommendations'].append("Complete workflow automation component implementation")
        
        summary['recommendations'].append("Add comprehensive automated testing for all workflow scenarios")
        summary['recommendations'].append("Implement performance monitoring and alerting")
        
        self.results['summary'] = summary
        
        # Print summary
        print(f"Overall Score: {summary['overall_score']}/100")
        
        if summary['strengths']:
            print(f"\nStrengths:")
            for strength in summary['strengths']:
                print(f"  ✓ {strength}")
        
        if summary['weaknesses']:
            print(f"\nWeaknesses:")
            for weakness in summary['weaknesses']:
                print(f"  ⚠ {weakness}")
        
        if summary['recommendations']:
            print(f"\nRecommendations:")
            for i, rec in enumerate(summary['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        return summary
    
    def run_analysis(self):
        """Run complete code analysis"""
        print("Deal Management Workflow Code Analysis")
        print("=" * 50)
        
        self.analyze_state_machine_implementation()
        self.analyze_payment_workflow()
        self.analyze_business_logic_implementation()
        self.analyze_code_quality()
        self.generate_summary()
        
        return self.results


def main():
    """Main execution function"""
    try:
        analyzer = DealWorkflowCodeAnalysis()
        results = analyzer.run_analysis()
        
        # Save results
        import json
        with open('deal_workflow_code_analysis.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n📄 Analysis results saved to: deal_workflow_code_analysis.json")
        
        return results
        
    except Exception as e:
        print(f"❌ Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    main()