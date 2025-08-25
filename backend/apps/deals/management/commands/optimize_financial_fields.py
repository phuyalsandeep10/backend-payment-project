"""
Financial Field Optimization Management Command
Provides tools for financial field validation, integrity checks, and optimization
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from apps.deals.models import Deal, Payment
from commission.models import Commission
from deals.financial_optimizer import FinancialFieldOptimizer
from apps.organization.models import Organization
import logging

logger = logging.getLogger('financial')

class Command(BaseCommand):
    help = 'Financial field optimization and integrity checking tools'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['validate', 'fix', 'report', 'audit'],
            required=True,
            help='Action to perform'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Organization ID to process (optional, processes all if not specified)'
        )
        
        parser.add_argument(
            '--model',
            type=str,
            choices=['deal', 'payment', 'commission', 'all'],
            default='all',
            help='Model to process'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Perform a dry run without making changes'
        )
        
        parser.add_argument(
            '--limit',
            type=int,
            default=1000,
            help='Limit number of records to process'
        )

    def handle(self, *args, **options):
        action = options['action']
        organization_id = options.get('organization_id')
        model_type = options['model']
        dry_run = options.get('dry_run', True)
        limit = options.get('limit', 1000)
        
        self.stdout.write(f"Running financial field optimization: {action}")
        self.stdout.write(f"Model: {model_type}, Dry run: {dry_run}, Limit: {limit}")
        
        # Get organizations to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
            if not organizations.exists():
                self.stdout.write(
                    self.style.ERROR(f'Organization with ID {organization_id} not found')
                )
                return
        else:
            organizations = Organization.objects.all()
        
        for organization in organizations:
            self.stdout.write(f"\nProcessing organization: {organization.name}")
            
            try:
                if action == 'validate':
                    self.validate_financial_fields(organization, model_type, limit)
                elif action == 'fix':
                    self.fix_financial_fields(organization, model_type, dry_run, limit)
                elif action == 'report':
                    self.generate_financial_report(organization, model_type)
                elif action == 'audit':
                    self.audit_financial_integrity(organization, model_type)
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error processing {organization.name}: {str(e)}')
                )
                logger.error(f"Financial optimization error for {organization.name}: {str(e)}")

    def validate_financial_fields(self, organization, model_type, limit):
        """Validate financial fields without making changes"""
        self.stdout.write(f"  Validating financial fields...")
        
        validation_errors = []
        
        if model_type in ['deal', 'all']:
            deals = Deal.objects.filter(organization=organization)[:limit]
            for deal in deals:
                try:
                    # Validate deal value
                    FinancialFieldOptimizer.validate_deal_value(deal.deal_value)
                    
                    # Validate payment consistency
                    payments = [{'amount': p.received_amount} for p in deal.payments.all()]
                    if payments:
                        FinancialFieldOptimizer.validate_payment_consistency(deal.deal_value, payments)
                        
                except Exception as e:
                    validation_errors.append({
                        'model': 'Deal',
                        'id': str(deal.id),
                        'error': str(e)
                    })
        
        if model_type in ['payment', 'all']:
            payments = Payment.objects.filter(deal__organization=organization)[:limit]
            for payment in payments:
                try:
                    FinancialFieldOptimizer.validate_payment_amount(
                        payment.received_amount, payment.deal.deal_value
                    )
                except Exception as e:
                    validation_errors.append({
                        'model': 'Payment',
                        'id': payment.id,
                        'error': str(e)
                    })
        
        if model_type in ['commission', 'all']:
            commissions = Commission.objects.filter(organization=organization)[:limit]
            for commission in commissions:
                try:
                    FinancialFieldOptimizer.validate_commission_rate(commission.commission_rate)
                    FinancialFieldOptimizer.validate_exchange_rate(commission.exchange_rate)
                except Exception as e:
                    validation_errors.append({
                        'model': 'Commission',
                        'id': commission.id,
                        'error': str(e)
                    })
        
        self.stdout.write(f"    Validation completed. Found {len(validation_errors)} errors.")
        
        if validation_errors:
            self.stdout.write("    First 10 errors:")
            for error in validation_errors[:10]:
                self.stdout.write(f"      {error['model']} {error['id']}: {error['error']}")

    def fix_financial_fields(self, organization, model_type, dry_run, limit):
        """Fix financial field inconsistencies"""
        action_text = "Would fix" if dry_run else "Fixing"
        self.stdout.write(f"  {action_text} financial field inconsistencies...")
        
        fixes_applied = 0
        
        if model_type in ['deal', 'all']:
            deals = Deal.objects.filter(organization=organization)[:limit]
            result = FinancialFieldOptimizer.fix_financial_inconsistencies(deals, dry_run)
            fixes_applied += result['summary']['total_fixes']
            
            self.stdout.write(f"    Deal fixes: {result['summary']['total_fixes']}")
            if result['summary']['failed_fixes'] > 0:
                self.stdout.write(f"    Deal fix failures: {result['summary']['failed_fixes']}")
        
        if model_type in ['commission', 'all']:
            commissions = Commission.objects.filter(organization=organization)[:limit]
            commission_fixes = 0
            
            for commission in commissions:
                try:
                    original_rate = commission.commission_rate
                    original_exchange = commission.exchange_rate
                    
                    # Validate and fix commission rate
                    validated_rate = FinancialFieldOptimizer.validate_commission_rate(commission.commission_rate)
                    validated_exchange = FinancialFieldOptimizer.validate_exchange_rate(commission.exchange_rate)
                    
                    if original_rate != validated_rate or original_exchange != validated_exchange:
                        if not dry_run:
                            commission.commission_rate = validated_rate
                            commission.exchange_rate = validated_exchange
                            commission.save()
                        commission_fixes += 1
                        
                except Exception as e:
                    logger.error(f"Failed to fix commission {commission.id}: {str(e)}")
            
            fixes_applied += commission_fixes
            self.stdout.write(f"    Commission fixes: {commission_fixes}")
        
        if dry_run:
            self.stdout.write(f"    DRY RUN: Would apply {fixes_applied} fixes")
        else:
            self.stdout.write(self.style.SUCCESS(f"    Applied {fixes_applied} fixes"))

    def generate_financial_report(self, organization, model_type):
        """Generate comprehensive financial integrity report"""
        self.stdout.write(f"  Generating financial integrity report...")
        
        if model_type in ['deal', 'all']:
            deals = Deal.objects.filter(organization=organization)
            report = FinancialFieldOptimizer.get_financial_integrity_report(deals)
            
            self.stdout.write(f"    Deal Financial Report:")
            self.stdout.write(f"      Total deals: {report['total_deals']}")
            self.stdout.write(f"      Total deal value: ${report['total_deal_value']:,.2f}")
            self.stdout.write(f"      Total payments: ${report['total_payments']:,.2f}")
            self.stdout.write(f"      Overpaid deals: {report['summary']['overpaid_deals']}")
            self.stdout.write(f"      Fully paid deals: {report['summary']['fully_paid_deals']}")
            self.stdout.write(f"      Underpaid deals: {report['summary']['underpaid_deals']}")
            
            if report['summary'].get('overpaid_percentage'):
                self.stdout.write(f"      Overpaid percentage: {report['summary']['overpaid_percentage']:.2f}%")
            
            if report['deals_with_issues']:
                self.stdout.write(f"      Issues found: {len(report['deals_with_issues'])}")
                for issue in report['deals_with_issues'][:5]:
                    self.stdout.write(f"        Deal {issue['deal_id']}: {issue['issue']}")
        
        if model_type in ['commission', 'all']:
            commissions = Commission.objects.filter(organization=organization)
            
            total_commissions = commissions.count()
            total_sales = sum(float(c.total_sales) for c in commissions)
            total_commission_amount = sum(float(c.total_commission) for c in commissions)
            
            self.stdout.write(f"    Commission Financial Report:")
            self.stdout.write(f"      Total commissions: {total_commissions}")
            self.stdout.write(f"      Total sales: ${total_sales:,.2f}")
            self.stdout.write(f"      Total commission amount: ${total_commission_amount:,.2f}")
            
            if total_sales > 0:
                avg_rate = (total_commission_amount / total_sales) * 100
                self.stdout.write(f"      Average effective rate: {avg_rate:.2f}%")

    def audit_financial_integrity(self, organization, model_type):
        """Perform comprehensive financial integrity audit"""
        self.stdout.write(f"  Performing financial integrity audit...")
        
        audit_issues = []
        
        if model_type in ['deal', 'all']:
            # Check for deals with inconsistent payment status
            deals = Deal.objects.filter(organization=organization)
            
            for deal in deals:
                try:
                    total_paid = deal.get_total_paid_amount()
                    deal_value = float(deal.deal_value)
                    
                    # Check payment status consistency
                    if deal.payment_status == 'full_payment' and abs(total_paid - deal_value) > 0.01:
                        audit_issues.append({
                            'type': 'payment_status_mismatch',
                            'deal_id': str(deal.id),
                            'issue': f'Marked as full payment but paid {total_paid} of {deal_value}'
                        })
                    
                    # Check for overpayments
                    if total_paid > deal_value + 0.01:
                        audit_issues.append({
                            'type': 'overpayment',
                            'deal_id': str(deal.id),
                            'issue': f'Overpaid by {total_paid - deal_value:.2f}'
                        })
                    
                except Exception as e:
                    audit_issues.append({
                        'type': 'calculation_error',
                        'deal_id': str(deal.id),
                        'issue': f'Error calculating payments: {str(e)}'
                    })
        
        if model_type in ['commission', 'all']:
            # Check commission calculation accuracy
            commissions = Commission.objects.filter(organization=organization)
            
            for commission in commissions:
                try:
                    # Recalculate commission to check accuracy
                    expected_amount = FinancialFieldOptimizer.calculate_commission_amount(
                        commission.total_sales, commission.commission_rate
                    )
                    
                    if abs(commission.commission_amount - expected_amount) > Decimal('0.01'):
                        audit_issues.append({
                            'type': 'commission_calculation_error',
                            'commission_id': commission.id,
                            'issue': f'Expected {expected_amount}, got {commission.commission_amount}'
                        })
                        
                except Exception as e:
                    audit_issues.append({
                        'type': 'commission_validation_error',
                        'commission_id': commission.id,
                        'issue': f'Validation error: {str(e)}'
                    })
        
        self.stdout.write(f"    Audit completed. Found {len(audit_issues)} issues.")
        
        # Group issues by type
        issue_types = {}
        for issue in audit_issues:
            issue_type = issue['type']
            if issue_type not in issue_types:
                issue_types[issue_type] = []
            issue_types[issue_type].append(issue)
        
        for issue_type, issues in issue_types.items():
            self.stdout.write(f"      {issue_type}: {len(issues)} issues")
            for issue in issues[:3]:  # Show first 3 of each type
                self.stdout.write(f"        {issue['issue']}")
        
        if audit_issues:
            self.stdout.write(
                self.style.WARNING(f"    Audit found {len(audit_issues)} financial integrity issues")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS("    No financial integrity issues found")
            )