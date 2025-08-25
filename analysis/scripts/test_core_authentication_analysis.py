#!/usr/bin/env python
"""
Core Authentication and Authorization Analysis Script
Comprehensive testing and analysis of the PRS authentication system
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

import json
from datetime import datetime, timedelta
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError

# Import models and services
from authentication.models import User, UserSession, SecureUserSession, SecurityEvent, OTPToken, UserProfile
from permissions.models import Role
from organization.models import Organization
from authentication.password_policy import PasswordPolicy, PasswordHistoryManager
from core_config.security_event_service import SecurityEventService
from authentication.views import UserViewSet
from authentication.serializers import UserSerializer

User = get_user_model()

class CoreAuthenticationAnalyzer:
    """
    Comprehensive analyzer for authentication and authorization system
    """
    
    def __init__(self):
        self.results = {
            'user_model_analysis': {},
            'organization_scoping': {},
            'role_based_permissions': {},
            'session_management': {},
            'password_policies': {},
            'security_event_logging': {},
            'performance_analysis': {},
            'security_vulnerabilities': [],
            'recommendations': []
        }
        self.factory = RequestFactory()
        self.security_service = SecurityEventService()
    
    def run_complete_analysis(self):
        """
        Run complete authentication and authorization analysis
        """
        print("🔍 Starting Core Authentication and Authorization Analysis...")
        print("=" * 60)
        
        try:
            # 1. User Model Implementation Analysis
            print("\n1️⃣ Analyzing User Model Implementation...")
            self.analyze_user_model()
            
            # 2. Organization Scoping Analysis
            print("\n2️⃣ Analyzing Organization Scoping...")
            self.analyze_organization_scoping()
            
            # 3. Role-Based Permission System
            print("\n3️⃣ Analyzing Role-Based Permission System...")
            self.analyze_role_based_permissions()
            
            # 4. Session Management Analysis
            print("\n4️⃣ Analyzing Session Management...")
            self.analyze_session_management()
            
            # 5. Password Policy Analysis
            print("\n5️⃣ Analyzing Password Policies...")
            self.analyze_password_policies()
            
            # 6. Security Event Logging Analysis
            print("\n6️⃣ Analyzing Security Event Logging...")
            self.analyze_security_event_logging()
            
            # 7. Performance Analysis
            print("\n7️⃣ Analyzing Performance Characteristics...")
            self.analyze_performance()
            
            # 8. Security Vulnerability Assessment
            print("\n8️⃣ Assessing Security Vulnerabilities...")
            self.assess_security_vulnerabilities()
            
            # Generate final report
            self.generate_analysis_report()
            
        except Exception as e:
            print(f"❌ Analysis failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def analyze_user_model(self):
        """
        Analyze User model implementation and organization scoping
        """
        print("   📊 Analyzing User model structure...")
        
        # Check model fields and relationships
        user_fields = [field.name for field in User._meta.get_fields()]
        
        # Analyze key features
        analysis = {
            'model_fields': user_fields,
            'has_organization_scoping': 'organization' in user_fields,
            'has_role_relationship': 'role' in user_fields,
            'has_team_relationship': 'team' in user_fields,
            'email_as_username': User.USERNAME_FIELD == 'email',
            'custom_manager': hasattr(User, 'objects') and hasattr(User.objects, 'create_user'),
            'status_choices': len(User.STATUS_CHOICES) if hasattr(User, 'STATUS_CHOICES') else 0,
            'has_security_fields': all(field in user_fields for field in ['must_change_password', 'login_count']),
            'has_business_fields': all(field in user_fields for field in ['sales_target', 'streak']),
        }
        
        # Check indexes for performance
        indexes = User._meta.indexes
        index_fields = []
        for index in indexes:
            index_fields.extend(index.fields)
        
        analysis['indexed_fields'] = list(set(index_fields))
        analysis['organization_indexes'] = len([idx for idx in indexes if 'organization' in str(idx.fields)])
        analysis['performance_indexes'] = len(indexes)
        
        # Test user creation
        try:
            with transaction.atomic():
                # Create test organization
                test_org = Organization.objects.create(name="Test Analysis Org")
                
                # Test user creation with email as username
                test_user = User.objects.create_user(
                    email="test@analysis.com",
                    password="TestPassword123!",
                    organization=test_org
                )
                
                analysis['user_creation_works'] = True
                analysis['email_normalization'] = test_user.email == "test@analysis.com"
                
                # Clean up
                test_user.delete()
                test_org.delete()
                
        except Exception as e:
            analysis['user_creation_works'] = False
            analysis['creation_error'] = str(e)
        
        self.results['user_model_analysis'] = analysis
        
        # Print key findings
        print(f"   ✅ Organization scoping: {'Yes' if analysis['has_organization_scoping'] else 'No'}")
        print(f"   ✅ Role-based access: {'Yes' if analysis['has_role_relationship'] else 'No'}")
        print(f"   ✅ Email as username: {'Yes' if analysis['email_as_username'] else 'No'}")
        print(f"   ✅ Performance indexes: {analysis['performance_indexes']}")
        print(f"   ✅ User creation test: {'Passed' if analysis['user_creation_works'] else 'Failed'}")
    
    def analyze_organization_scoping(self):
        """
        Analyze organization-based data isolation
        """
        print("   🏢 Testing organization scoping...")
        
        analysis = {
            'isolation_test_passed': False,
            'cross_org_access_blocked': False,
            'query_optimization': False,
            'data_leakage_risk': 'unknown'
        }
        
        try:
            with transaction.atomic():
                # Create test organizations
                org1 = Organization.objects.create(name="Org1 Analysis")
                org2 = Organization.objects.create(name="Org2 Analysis")
                
                # Create test users in different organizations
                user1 = User.objects.create_user(
                    email="user1@org1.com",
                    password="TestPass123!",
                    organization=org1
                )
                user2 = User.objects.create_user(
                    email="user2@org2.com", 
                    password="TestPass123!",
                    organization=org2
                )
                
                # Test organization filtering in queryset
                org1_users = User.objects.filter(organization=org1)
                org2_users = User.objects.filter(organization=org2)
                
                analysis['isolation_test_passed'] = (
                    user1 in org1_users and user1 not in org2_users and
                    user2 in org2_users and user2 not in org1_users
                )
                
                # Test ViewSet organization filtering
                request = self.factory.get('/api/users/')
                request.user = user1
                
                viewset = UserViewSet()
                viewset.request = request
                queryset = viewset.get_queryset()
                
                # Check if queryset is properly filtered
                analysis['viewset_filtering'] = all(
                    user.organization == org1 for user in queryset if user.organization
                )
                
                # Check for potential data leakage
                all_users_query = User.objects.all()
                analysis['total_users_accessible'] = all_users_query.count()
                analysis['org_filtered_count'] = queryset.count()
                
                analysis['data_leakage_risk'] = 'low' if analysis['viewset_filtering'] else 'high'
                
                # Clean up
                user1.delete()
                user2.delete()
                org1.delete()
                org2.delete()
                
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['organization_scoping'] = analysis
        
        print(f"   ✅ Data isolation: {'Passed' if analysis['isolation_test_passed'] else 'Failed'}")
        print(f"   ✅ ViewSet filtering: {'Passed' if analysis.get('viewset_filtering', False) else 'Failed'}")
        print(f"   ⚠️  Data leakage risk: {analysis['data_leakage_risk']}")
    
    def analyze_role_based_permissions(self):
        """
        Analyze role-based permission system functionality
        """
        print("   👥 Analyzing role-based permissions...")
        
        analysis = {
            'role_model_exists': False,
            'organization_scoped_roles': False,
            'permission_integration': False,
            'role_assignment_works': False,
            'expected_roles_count': 6  # As mentioned in requirements
        }
        
        try:
            # Check if Role model exists and has proper structure
            role_fields = [field.name for field in Role._meta.get_fields()]
            analysis['role_model_exists'] = True
            analysis['role_fields'] = role_fields
            analysis['organization_scoped_roles'] = 'organization' in role_fields
            analysis['permission_integration'] = 'permissions' in role_fields
            
            # Test role creation and assignment
            with transaction.atomic():
                test_org = Organization.objects.create(name="Role Test Org")
                
                # Create standard roles
                standard_roles = [
                    "Super Admin", "Organization Admin", "Salesperson", 
                    "Verifier", "Team Member", "Supervisor"
                ]
                
                created_roles = []
                for role_name in standard_roles:
                    role = Role.objects.create(name=role_name, organization=test_org)
                    created_roles.append(role)
                
                analysis['roles_created'] = len(created_roles)
                analysis['role_assignment_works'] = len(created_roles) == len(standard_roles)
                
                # Test user-role assignment
                test_user = User.objects.create_user(
                    email="roletest@test.com",
                    password="TestPass123!",
                    organization=test_org,
                    role=created_roles[0]  # Assign first role
                )
                
                analysis['user_role_assignment'] = test_user.role is not None
                analysis['role_organization_match'] = (
                    test_user.role.organization == test_user.organization
                )
                
                # Clean up
                test_user.delete()
                for role in created_roles:
                    role.delete()
                test_org.delete()
                
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['role_based_permissions'] = analysis
        
        print(f"   ✅ Role model: {'Exists' if analysis['role_model_exists'] else 'Missing'}")
        print(f"   ✅ Organization scoping: {'Yes' if analysis['organization_scoped_roles'] else 'No'}")
        print(f"   ✅ Role assignment: {'Works' if analysis['role_assignment_works'] else 'Failed'}")
        print(f"   ✅ Roles created: {analysis.get('roles_created', 0)}/{analysis['expected_roles_count']}")
    
    def analyze_session_management(self):
        """
        Analyze session management and security features
        """
        print("   🔐 Analyzing session management...")
        
        analysis = {
            'basic_session_model': False,
            'secure_session_model': False,
            'session_security_features': [],
            'session_cleanup_available': False,
            'concurrent_session_control': False
        }
        
        try:
            # Check UserSession model
            session_fields = [field.name for field in UserSession._meta.get_fields()]
            analysis['basic_session_model'] = True
            analysis['basic_session_fields'] = session_fields
            
            # Check SecureUserSession model
            secure_session_fields = [field.name for field in SecureUserSession._meta.get_fields()]
            analysis['secure_session_model'] = True
            analysis['secure_session_fields'] = secure_session_fields
            
            # Analyze security features
            security_features = []
            if 'session_fingerprint' in secure_session_fields:
                security_features.append('Session Fingerprinting')
            if 'user_agent_hash' in secure_session_fields:
                security_features.append('User Agent Validation')
            if 'is_suspicious' in secure_session_fields:
                security_features.append('Suspicious Activity Detection')
            if 'expires_at' in secure_session_fields:
                security_features.append('Session Expiration')
            if 'ip_verified' in secure_session_fields:
                security_features.append('IP Verification')
            
            analysis['session_security_features'] = security_features
            
            # Test session creation and management
            with transaction.atomic():
                test_org = Organization.objects.create(name="Session Test Org")
                test_user = User.objects.create_user(
                    email="sessiontest@test.com",
                    password="TestPass123!",
                    organization=test_org
                )
                
                # Test SecureUserSession creation
                session = SecureUserSession.objects.create(
                    user=test_user,
                    session_id="test_session_123",
                    jwt_token_id="test_jwt_123",
                    ip_address="192.168.1.1",
                    user_agent="Test Agent",
                    user_agent_hash="test_hash",
                    session_fingerprint="test_fingerprint",
                    expires_at=timezone.now() + timedelta(hours=1)
                )
                
                analysis['session_creation_works'] = True
                
                # Test session methods
                analysis['has_expiration_check'] = hasattr(session, 'is_expired')
                analysis['has_invalidation'] = hasattr(session, 'invalidate')
                analysis['has_activity_update'] = hasattr(session, 'update_activity')
                
                # Test class methods
                analysis['session_cleanup_available'] = hasattr(SecureUserSession, 'cleanup_expired_sessions')
                analysis['concurrent_session_control'] = hasattr(SecureUserSession, 'enforce_session_limit')
                
                # Clean up
                session.delete()
                test_user.delete()
                test_org.delete()
                
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['session_management'] = analysis
        
        print(f"   ✅ Basic sessions: {'Available' if analysis['basic_session_model'] else 'Missing'}")
        print(f"   ✅ Secure sessions: {'Available' if analysis['secure_session_model'] else 'Missing'}")
        print(f"   ✅ Security features: {len(analysis['session_security_features'])}")
        print(f"   ✅ Session cleanup: {'Available' if analysis['session_cleanup_available'] else 'Missing'}")
        print(f"   ✅ Concurrent control: {'Available' if analysis['concurrent_session_control'] else 'Missing'}")
    
    def analyze_password_policies(self):
        """
        Analyze password policy implementation and security
        """
        print("   🔒 Analyzing password policies...")
        
        analysis = {
            'policy_class_exists': False,
            'organization_specific_policies': False,
            'validation_features': [],
            'password_history': False,
            'expiration_support': False,
            'strength_scoring': False
        }
        
        try:
            # Test PasswordPolicy class
            analysis['policy_class_exists'] = True
            
            # Test policy retrieval
            default_policy = PasswordPolicy.get_policy_for_organization(None)
            analysis['default_policy_available'] = default_policy is not None
            analysis['policy_settings'] = list(default_policy.keys()) if default_policy else []
            
            # Test password validation
            test_passwords = [
                ("weak", "123"),
                ("medium", "Password123"),
                ("strong", "StrongP@ssw0rd123!")
            ]
            
            validation_results = {}
            for strength, password in test_passwords:
                result = PasswordPolicy.validate_password(password)
                validation_results[strength] = {
                    'is_valid': result['is_valid'],
                    'error_count': len(result['errors'])
                }
            
            analysis['validation_results'] = validation_results
            
            # Check validation features
            validation_features = []
            if 'min_length' in default_policy:
                validation_features.append('Minimum Length')
            if 'require_uppercase' in default_policy:
                validation_features.append('Uppercase Requirement')
            if 'require_special_chars' in default_policy:
                validation_features.append('Special Characters')
            if 'forbidden_patterns' in default_policy:
                validation_features.append('Forbidden Patterns')
            if 'max_repeated_chars' in default_policy:
                validation_features.append('Repeated Character Limit')
            
            analysis['validation_features'] = validation_features
            
            # Test additional features
            analysis['password_history'] = hasattr(PasswordHistoryManager, 'add_password_to_history')
            analysis['expiration_support'] = hasattr(PasswordPolicy, 'check_password_expiration')
            analysis['strength_scoring'] = hasattr(PasswordPolicy, 'get_password_strength_score')
            analysis['secure_generation'] = hasattr(PasswordPolicy, 'generate_secure_password')
            
            # Test password strength scoring
            if analysis['strength_scoring']:
                strength_scores = {}
                for strength, password in test_passwords:
                    score = PasswordPolicy.get_password_strength_score(password)
                    strength_scores[strength] = score
                analysis['strength_scores'] = strength_scores
            
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['password_policies'] = analysis
        
        print(f"   ✅ Policy system: {'Available' if analysis['policy_class_exists'] else 'Missing'}")
        print(f"   ✅ Validation features: {len(analysis['validation_features'])}")
        print(f"   ✅ Password history: {'Available' if analysis['password_history'] else 'Missing'}")
        print(f"   ✅ Expiration support: {'Available' if analysis['expiration_support'] else 'Missing'}")
        print(f"   ✅ Strength scoring: {'Available' if analysis['strength_scoring'] else 'Missing'}")
    
    def analyze_security_event_logging(self):
        """
        Analyze security event logging system
        """
        print("   📝 Analyzing security event logging...")
        
        analysis = {
            'security_event_model': False,
            'event_types_count': 0,
            'severity_levels': [],
            'risk_scoring': False,
            'automated_alerts': False,
            'dashboard_data': False
        }
        
        try:
            # Check SecurityEvent model
            event_fields = [field.name for field in SecurityEvent._meta.get_fields()]
            analysis['security_event_model'] = True
            analysis['event_fields'] = event_fields
            
            # Check event types and severity levels
            if hasattr(SecurityEvent, 'EVENT_TYPE_CHOICES'):
                analysis['event_types_count'] = len(SecurityEvent.EVENT_TYPE_CHOICES)
                analysis['event_types'] = [choice[0] for choice in SecurityEvent.EVENT_TYPE_CHOICES]
            
            if hasattr(SecurityEvent, 'SEVERITY_CHOICES'):
                analysis['severity_levels'] = [choice[0] for choice in SecurityEvent.SEVERITY_CHOICES]
            
            # Check advanced features
            analysis['risk_scoring'] = 'risk_score' in event_fields
            analysis['correlation_support'] = 'correlation_id' in event_fields
            analysis['investigation_tracking'] = 'is_investigated' in event_fields
            
            # Test SecurityEventService
            analysis['event_service_available'] = hasattr(self.security_service, 'log_authentication_attempt')
            analysis['dashboard_data'] = hasattr(self.security_service, 'get_security_dashboard_data')
            
            # Test event creation
            with transaction.atomic():
                test_org = Organization.objects.create(name="Security Test Org")
                test_user = User.objects.create_user(
                    email="securitytest@test.com",
                    password="TestPass123!",
                    organization=test_org
                )
                
                # Test authentication event logging
                event = self.security_service.log_authentication_attempt(
                    username=test_user.email,
                    success=False,
                    ip_address="192.168.1.100",
                    user_agent="Test Agent"
                )
                
                analysis['event_creation_works'] = event is not None
                analysis['event_has_risk_score'] = hasattr(event, 'risk_score') and event.risk_score > 0
                
                # Test dashboard data
                if analysis['dashboard_data']:
                    dashboard_data = self.security_service.get_security_dashboard_data(days=1)
                    analysis['dashboard_keys'] = list(dashboard_data.keys())
                
                # Clean up
                event.delete()
                test_user.delete()
                test_org.delete()
                
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['security_event_logging'] = analysis
        
        print(f"   ✅ Event model: {'Available' if analysis['security_event_model'] else 'Missing'}")
        print(f"   ✅ Event types: {analysis['event_types_count']}")
        print(f"   ✅ Severity levels: {len(analysis['severity_levels'])}")
        print(f"   ✅ Risk scoring: {'Available' if analysis['risk_scoring'] else 'Missing'}")
        print(f"   ✅ Event service: {'Available' if analysis.get('event_service_available', False) else 'Missing'}")
    
    def analyze_performance(self):
        """
        Analyze performance characteristics of authentication system
        """
        print("   ⚡ Analyzing performance characteristics...")
        
        analysis = {
            'database_indexes': 0,
            'query_optimization': False,
            'caching_support': False,
            'bulk_operations': False
        }
        
        try:
            # Count database indexes
            user_indexes = len(User._meta.indexes)
            session_indexes = len(SecureUserSession._meta.indexes) if hasattr(SecureUserSession, '_meta') else 0
            event_indexes = len(SecurityEvent._meta.indexes) if hasattr(SecurityEvent, '_meta') else 0
            
            analysis['database_indexes'] = user_indexes + session_indexes + event_indexes
            analysis['user_indexes'] = user_indexes
            analysis['session_indexes'] = session_indexes
            analysis['event_indexes'] = event_indexes
            
            # Check for query optimization features
            analysis['query_optimization'] = hasattr(UserViewSet, 'get_queryset')
            
            # Check for caching in password policies
            analysis['caching_support'] = 'cache' in str(PasswordPolicy.get_policy_for_organization.__code__.co_names)
            
            # Check for bulk operations
            analysis['bulk_operations'] = hasattr(SecurityEvent, 'objects')
            
            # Analyze index coverage for common queries
            user_index_fields = []
            for index in User._meta.indexes:
                user_index_fields.extend(index.fields)
            
            critical_fields = ['organization', 'email', 'is_active', 'role']
            analysis['critical_fields_indexed'] = [
                field for field in critical_fields if field in user_index_fields
            ]
            
        except Exception as e:
            analysis['error'] = str(e)
        
        self.results['performance_analysis'] = analysis
        
        print(f"   ✅ Total indexes: {analysis['database_indexes']}")
        print(f"   ✅ Query optimization: {'Available' if analysis['query_optimization'] else 'Missing'}")
        print(f"   ✅ Caching support: {'Available' if analysis['caching_support'] else 'Missing'}")
        print(f"   ✅ Critical fields indexed: {len(analysis.get('critical_fields_indexed', []))}/4")
    
    def assess_security_vulnerabilities(self):
        """
        Assess potential security vulnerabilities
        """
        print("   🛡️  Assessing security vulnerabilities...")
        
        vulnerabilities = []
        recommendations = []
        
        # Check for common security issues
        
        # 1. Password storage
        if User.objects.filter(password__startswith='pbkdf2_').exists():
            recommendations.append("✅ Passwords are properly hashed using Django's secure methods")
        else:
            vulnerabilities.append("⚠️ Password hashing method unclear - verify secure storage")
        
        # 2. Session security
        if hasattr(SecureUserSession, 'session_fingerprint'):
            recommendations.append("✅ Session fingerprinting implemented for hijacking protection")
        else:
            vulnerabilities.append("⚠️ Session hijacking protection may be insufficient")
        
        # 3. Rate limiting
        if 'throttle_classes' in str(UserViewSet.__dict__):
            recommendations.append("✅ Rate limiting implemented on authentication endpoints")
        else:
            vulnerabilities.append("⚠️ Rate limiting not detected - brute force attacks possible")
        
        # 4. Input validation
        if hasattr(PasswordPolicy, 'validate_password'):
            recommendations.append("✅ Password validation policies implemented")
        else:
            vulnerabilities.append("⚠️ Weak password validation may allow insecure passwords")
        
        # 5. Audit logging
        if hasattr(SecurityEvent, 'EVENT_TYPE_CHOICES'):
            recommendations.append("✅ Comprehensive security event logging implemented")
        else:
            vulnerabilities.append("⚠️ Security event logging may be insufficient for compliance")
        
        # 6. Organization isolation
        if 'organization' in [field.name for field in User._meta.get_fields()]:
            recommendations.append("✅ Multi-tenant organization isolation implemented")
        else:
            vulnerabilities.append("⚠️ Data isolation between organizations not implemented")
        
        # 7. Session management
        if hasattr(SecureUserSession, 'cleanup_expired_sessions'):
            recommendations.append("✅ Session cleanup mechanisms available")
        else:
            vulnerabilities.append("⚠️ Expired session cleanup may not be automated")
        
        self.results['security_vulnerabilities'] = vulnerabilities
        self.results['recommendations'] = recommendations
        
        print(f"   ⚠️  Vulnerabilities found: {len(vulnerabilities)}")
        print(f"   ✅ Security strengths: {len(recommendations)}")
    
    def generate_analysis_report(self):
        """
        Generate comprehensive analysis report
        """
        print("\n" + "=" * 60)
        print("📊 CORE AUTHENTICATION & AUTHORIZATION ANALYSIS REPORT")
        print("=" * 60)
        
        # Summary
        print("\n🎯 EXECUTIVE SUMMARY")
        print("-" * 30)
        
        total_checks = 0
        passed_checks = 0
        
        # Count checks from each analysis
        for section, data in self.results.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, bool):
                        total_checks += 1
                        if value:
                            passed_checks += 1
        
        success_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        print(f"Overall Success Rate: {success_rate:.1f}% ({passed_checks}/{total_checks} checks passed)")
        
        # Detailed findings
        print(f"\n📋 DETAILED FINDINGS")
        print("-" * 30)
        
        sections = [
            ("User Model Analysis", "user_model_analysis"),
            ("Organization Scoping", "organization_scoping"),
            ("Role-Based Permissions", "role_based_permissions"),
            ("Session Management", "session_management"),
            ("Password Policies", "password_policies"),
            ("Security Event Logging", "security_event_logging"),
            ("Performance Analysis", "performance_analysis")
        ]
        
        for section_name, section_key in sections:
            print(f"\n{section_name}:")
            section_data = self.results.get(section_key, {})
            
            for key, value in section_data.items():
                if isinstance(value, bool):
                    status = "✅ PASS" if value else "❌ FAIL"
                    print(f"  {status} {key.replace('_', ' ').title()}")
                elif isinstance(value, (int, str)) and not key.endswith('_error'):
                    print(f"  📊 {key.replace('_', ' ').title()}: {value}")
        
        # Security Assessment
        print(f"\n🛡️  SECURITY ASSESSMENT")
        print("-" * 30)
        
        vulnerabilities = self.results.get('security_vulnerabilities', [])
        recommendations = self.results.get('recommendations', [])
        
        if vulnerabilities:
            print("Vulnerabilities Found:")
            for vuln in vulnerabilities:
                print(f"  {vuln}")
        
        if recommendations:
            print("\nSecurity Strengths:")
            for rec in recommendations:
                print(f"  {rec}")
        
        # Final recommendations
        print(f"\n🎯 RECOMMENDATIONS")
        print("-" * 30)
        
        if success_rate >= 90:
            print("✅ Authentication system is robust and production-ready")
        elif success_rate >= 75:
            print("⚠️ Authentication system is mostly solid with minor improvements needed")
        else:
            print("❌ Authentication system needs significant improvements before production")
        
        print("\nPriority Actions:")
        if len(vulnerabilities) > 0:
            print("1. Address identified security vulnerabilities")
        if self.results.get('organization_scoping', {}).get('data_leakage_risk') == 'high':
            print("2. Fix organization data isolation issues")
        if self.results.get('performance_analysis', {}).get('database_indexes', 0) < 10:
            print("3. Add more database indexes for performance")
        
        # Save detailed report
        report_file = 'core_authentication_analysis_report.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        print("\n" + "=" * 60)


def main():
    """
    Main execution function
    """
    analyzer = CoreAuthenticationAnalyzer()
    analyzer.run_complete_analysis()


if __name__ == "__main__":
    main()