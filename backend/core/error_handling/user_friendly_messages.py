"""
User-Friendly Error Message System for PRS Backend
Provides contextual, helpful, and actionable error messages for users
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from django.utils.translation import gettext as _
from django.conf import settings

from ..logging import StructuredLogger, EventType


class MessageTone(Enum):
    """Message tone/style"""
    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    TECHNICAL = "technical"
    APOLOGETIC = "apologetic"


class ActionType(Enum):
    """Types of user actions"""
    RETRY = "retry"
    CONTACT_SUPPORT = "contact_support"
    CHECK_INPUT = "check_input"
    WAIT = "wait"
    LOGIN = "login"
    UPGRADE = "upgrade"
    NAVIGATE = "navigate"


@dataclass
class UserAction:
    """Actionable item for users"""
    type: ActionType
    label: str
    description: str
    url: Optional[str] = None
    icon: Optional[str] = None
    primary: bool = False


@dataclass
class HelpResource:
    """Help resource for users"""
    title: str
    url: str
    type: str  # 'documentation', 'video', 'faq', 'tutorial'
    description: Optional[str] = None


@dataclass
class UserFriendlyMessage:
    """Complete user-friendly error message"""
    title: str
    message: str
    severity: str  # 'info', 'warning', 'error', 'critical'
    tone: MessageTone
    actions: List[UserAction]
    help_resources: List[HelpResource]
    context: Dict[str, Any]
    show_technical_details: bool = False
    estimated_resolution_time: Optional[str] = None


class MessageContextAnalyzer:
    """Analyzes context to provide better error messages"""
    
    def __init__(self):
        self.logger = StructuredLogger('message_context_analyzer')
    
    def analyze_user_context(self, user_id: int = None, session_data: Dict = None) -> Dict[str, Any]:
        """Analyze user context for message personalization"""
        context = {
            'user_type': 'anonymous',
            'experience_level': 'beginner',
            'preferred_language': 'en',
            'timezone': 'UTC',
            'device_type': 'desktop',
            'previous_errors': [],
            'current_workflow': None
        }
        
        if user_id:
            # Get user-specific context
            context.update(self._get_user_profile_context(user_id))
        
        if session_data:
            # Extract session context
            context.update(self._extract_session_context(session_data))
        
        return context
    
    def analyze_error_context(self, error: Exception, request_path: str = None, 
                             method: str = None) -> Dict[str, Any]:
        """Analyze error context to provide relevant information"""
        context = {
            'error_category': self._categorize_error(error),
            'affected_feature': self._identify_affected_feature(request_path),
            'user_intent': self._infer_user_intent(request_path, method),
            'complexity_level': self._assess_complexity(error),
            'business_impact': self._assess_business_impact(request_path),
            'recovery_difficulty': self._assess_recovery_difficulty(error)
        }
        
        return context
    
    def _get_user_profile_context(self, user_id: int) -> Dict[str, Any]:
        """Get user profile context"""
        # This would typically query the database
        # For now, return default context
        return {
            'user_type': 'registered',
            'experience_level': 'intermediate',
            'support_tier': 'standard'
        }
    
    def _extract_session_context(self, session_data: Dict) -> Dict[str, Any]:
        """Extract relevant context from session data"""
        context = {}
        
        if 'device_info' in session_data:
            context['device_type'] = session_data['device_info'].get('type', 'desktop')
        
        if 'user_agent' in session_data:
            context['browser'] = self._parse_browser(session_data['user_agent'])
        
        if 'recent_actions' in session_data:
            context['current_workflow'] = self._infer_workflow(session_data['recent_actions'])
        
        return context
    
    def _categorize_error(self, error: Exception) -> str:
        """Categorize error for context"""
        error_categories = {
            'ValidationError': 'input_validation',
            'PermissionDenied': 'access_control',
            'AuthenticationFailed': 'authentication',
            'DatabaseError': 'system_issue',
            'TimeoutError': 'performance',
            'ConnectionError': 'connectivity',
            'FileNotFoundError': 'resource_missing'
        }
        
        return error_categories.get(type(error).__name__, 'unknown')
    
    def _identify_affected_feature(self, request_path: str) -> str:
        """Identify which feature is affected"""
        if not request_path:
            return 'unknown'
        
        feature_map = {
            '/api/auth/': 'authentication',
            '/api/deals/': 'deal_management',
            '/api/payments/': 'payment_processing',
            '/api/clients/': 'client_management',
            '/api/reports/': 'reporting',
            '/api/users/': 'user_management',
            '/api/dashboard/': 'dashboard'
        }
        
        for path_prefix, feature in feature_map.items():
            if request_path.startswith(path_prefix):
                return feature
        
        return 'general'
    
    def _infer_user_intent(self, request_path: str, method: str) -> str:
        """Infer what the user was trying to do"""
        if not request_path or not method:
            return 'unknown'
        
        intent_map = {
            ('POST', 'auth'): 'login',
            ('POST', 'deals'): 'create_deal',
            ('PUT', 'deals'): 'update_deal',
            ('GET', 'deals'): 'view_deals',
            ('DELETE', 'deals'): 'delete_deal',
            ('POST', 'payments'): 'process_payment',
            ('GET', 'reports'): 'generate_report',
        }
        
        feature = self._identify_affected_feature(request_path)
        return intent_map.get((method, feature), f"{method.lower()}_{feature}")
    
    def _assess_complexity(self, error: Exception) -> str:
        """Assess the complexity level of the error"""
        simple_errors = ['ValidationError', 'PermissionDenied']
        complex_errors = ['DatabaseError', 'SystemError']
        
        error_type = type(error).__name__
        
        if error_type in simple_errors:
            return 'simple'
        elif error_type in complex_errors:
            return 'complex'
        else:
            return 'moderate'
    
    def _assess_business_impact(self, request_path: str) -> str:
        """Assess business impact of the error"""
        critical_paths = ['/api/payments/', '/api/deals/']
        important_paths = ['/api/clients/', '/api/auth/']
        
        if any(request_path.startswith(path) for path in critical_paths):
            return 'high'
        elif any(request_path.startswith(path) for path in important_paths):
            return 'medium'
        else:
            return 'low'
    
    def _assess_recovery_difficulty(self, error: Exception) -> str:
        """Assess how difficult it is for user to recover"""
        easy_recovery = ['ValidationError']
        hard_recovery = ['DatabaseError', 'SystemError']
        
        error_type = type(error).__name__
        
        if error_type in easy_recovery:
            return 'easy'
        elif error_type in hard_recovery:
            return 'hard'
        else:
            return 'moderate'
    
    def _parse_browser(self, user_agent: str) -> str:
        """Parse browser from user agent"""
        if 'Chrome' in user_agent:
            return 'chrome'
        elif 'Firefox' in user_agent:
            return 'firefox'
        elif 'Safari' in user_agent:
            return 'safari'
        else:
            return 'unknown'
    
    def _infer_workflow(self, recent_actions: List[Dict]) -> str:
        """Infer current workflow from recent actions"""
        if not recent_actions:
            return None
        
        # Simple workflow inference based on recent actions
        action_types = [action.get('type') for action in recent_actions[-3:]]
        
        workflows = {
            ['view_deals', 'create_deal']: 'deal_creation',
            ['login', 'view_dashboard']: 'getting_started',
            ['view_clients', 'create_payment']: 'payment_processing',
        }
        
        for pattern, workflow in workflows.items():
            if action_types[-len(pattern):] == pattern:
                return workflow
        
        return None


class MessageGenerator:
    """Generates user-friendly error messages"""
    
    def __init__(self):
        self.context_analyzer = MessageContextAnalyzer()
        self.logger = StructuredLogger('message_generator')
        
        # Load message templates
        self.templates = self._load_message_templates()
        self.action_templates = self._load_action_templates()
        self.help_resources = self._load_help_resources()
    
    def generate_message(self, error: Exception, user_context: Dict = None, 
                        error_context: Dict = None, tone: MessageTone = MessageTone.PROFESSIONAL) -> UserFriendlyMessage:
        """Generate user-friendly error message"""
        
        # Get error type and context
        error_type = type(error).__name__
        error_message = str(error)
        
        # Analyze contexts if not provided
        if not user_context:
            user_context = self.context_analyzer.analyze_user_context()
        
        if not error_context:
            error_context = self.context_analyzer.analyze_error_context(error)
        
        # Generate message components
        title = self._generate_title(error_type, error_context, tone)
        message = self._generate_message_text(error_type, error_message, error_context, user_context, tone)
        severity = self._determine_severity(error_type, error_context)
        actions = self._generate_actions(error_type, error_context, user_context)
        help_resources = self._get_relevant_help_resources(error_context['affected_feature'])
        
        # Estimate resolution time
        resolution_time = self._estimate_resolution_time(error_context)
        
        return UserFriendlyMessage(
            title=title,
            message=message,
            severity=severity,
            tone=tone,
            actions=actions,
            help_resources=help_resources,
            context={**user_context, **error_context},
            estimated_resolution_time=resolution_time
        )
    
    def _generate_title(self, error_type: str, error_context: Dict, tone: MessageTone) -> str:
        """Generate appropriate title for the error"""
        
        titles = {
            'ValidationError': {
                MessageTone.PROFESSIONAL: _("Please check your information"),
                MessageTone.FRIENDLY: _("Oops! Let's fix that information"),
                MessageTone.TECHNICAL: _("Validation Error"),
                MessageTone.APOLOGETIC: _("Sorry, there's an issue with your information")
            },
            'PermissionDenied': {
                MessageTone.PROFESSIONAL: _("Access not authorized"),
                MessageTone.FRIENDLY: _("You don't have access to this"),
                MessageTone.TECHNICAL: _("Permission Denied"),
                MessageTone.APOLOGETIC: _("Sorry, you don't have permission for this action")
            },
            'DatabaseError': {
                MessageTone.PROFESSIONAL: _("Service temporarily unavailable"),
                MessageTone.FRIENDLY: _("We're having a technical hiccup"),
                MessageTone.TECHNICAL: _("Database Error"),
                MessageTone.APOLOGETIC: _("We apologize for the technical difficulty")
            },
            'TimeoutError': {
                MessageTone.PROFESSIONAL: _("Request timed out"),
                MessageTone.FRIENDLY: _("That took too long to process"),
                MessageTone.TECHNICAL: _("Timeout Error"),
                MessageTone.APOLOGETIC: _("Sorry, that request took too long")
            }
        }
        
        error_titles = titles.get(error_type, {})
        return error_titles.get(tone, _("An error occurred"))
    
    def _generate_message_text(self, error_type: str, error_message: str, 
                              error_context: Dict, user_context: Dict, tone: MessageTone) -> str:
        """Generate detailed message text"""
        
        # Get base message template
        template_key = f"{error_type}_{tone.value}"
        base_template = self.templates.get(template_key, self.templates.get('default', ''))
        
        # Contextual information
        feature_name = self._get_feature_display_name(error_context.get('affected_feature', ''))
        user_intent = error_context.get('user_intent', '')
        
        # Generate contextual message
        context_messages = {
            'input_validation': self._generate_validation_message(error_message, feature_name, tone),
            'access_control': self._generate_access_message(feature_name, user_intent, tone),
            'system_issue': self._generate_system_message(feature_name, tone),
            'performance': self._generate_performance_message(feature_name, tone),
            'connectivity': self._generate_connectivity_message(tone)
        }
        
        error_category = error_context.get('error_category', 'unknown')
        contextual_message = context_messages.get(error_category, base_template)
        
        # Add personalization based on user context
        if user_context.get('experience_level') == 'beginner':
            contextual_message = self._add_beginner_context(contextual_message)
        
        return contextual_message
    
    def _generate_validation_message(self, error_message: str, feature_name: str, tone: MessageTone) -> str:
        """Generate message for validation errors"""
        
        # Extract specific validation issues
        validation_issues = self._extract_validation_issues(error_message)
        
        messages = {
            MessageTone.PROFESSIONAL: f"The information provided for {feature_name} doesn't meet our requirements. {validation_issues}",
            MessageTone.FRIENDLY: f"Let's fix the {feature_name} information. {validation_issues}",
            MessageTone.TECHNICAL: f"Validation failed: {validation_issues}",
            MessageTone.APOLOGETIC: f"We're sorry, but the {feature_name} information needs to be corrected. {validation_issues}"
        }
        
        return messages.get(tone, messages[MessageTone.PROFESSIONAL])
    
    def _generate_access_message(self, feature_name: str, user_intent: str, tone: MessageTone) -> str:
        """Generate message for access control errors"""
        
        messages = {
            MessageTone.PROFESSIONAL: f"You don't have permission to access {feature_name}. Please contact your administrator if you need access.",
            MessageTone.FRIENDLY: f"Looks like you don't have access to {feature_name}. Your admin can help with that!",
            MessageTone.TECHNICAL: f"Access denied for {feature_name}. Required permissions not found.",
            MessageTone.APOLOGETIC: f"We're sorry, but you don't have permission to access {feature_name}. Please contact support for assistance."
        }
        
        return messages.get(tone, messages[MessageTone.PROFESSIONAL])
    
    def _generate_system_message(self, feature_name: str, tone: MessageTone) -> str:
        """Generate message for system errors"""
        
        messages = {
            MessageTone.PROFESSIONAL: f"We're experiencing technical difficulties with {feature_name}. Our team has been notified and is working on a fix.",
            MessageTone.FRIENDLY: f"Oops! {feature_name} is having some technical issues. Don't worry, we're on it!",
            MessageTone.TECHNICAL: f"System error in {feature_name}. Check logs for details.",
            MessageTone.APOLOGETIC: f"We sincerely apologize for the technical issue with {feature_name}. We're working to resolve this as quickly as possible."
        }
        
        return messages.get(tone, messages[MessageTone.PROFESSIONAL])
    
    def _generate_performance_message(self, feature_name: str, tone: MessageTone) -> str:
        """Generate message for performance issues"""
        
        messages = {
            MessageTone.PROFESSIONAL: f"The {feature_name} request took too long to process. Please try again or reduce the amount of data being processed.",
            MessageTone.FRIENDLY: f"{feature_name} is taking longer than usual. Let's try that again!",
            MessageTone.TECHNICAL: f"Timeout occurred in {feature_name}. Check system performance and retry.",
            MessageTone.APOLOGETIC: f"We're sorry {feature_name} is running slowly. Please try again in a moment."
        }
        
        return messages.get(tone, messages[MessageTone.PROFESSIONAL])
    
    def _generate_connectivity_message(self, tone: MessageTone) -> str:
        """Generate message for connectivity issues"""
        
        messages = {
            MessageTone.PROFESSIONAL: "There seems to be a connectivity issue. Please check your internet connection and try again.",
            MessageTone.FRIENDLY: "Looks like there's a connection hiccup. Check your internet and give it another try!",
            MessageTone.TECHNICAL: "Network connectivity error. Verify connection and retry request.",
            MessageTone.APOLOGETIC: "We're sorry, but there appears to be a connection issue. Please check your network and try again."
        }
        
        return messages.get(tone, messages[MessageTone.PROFESSIONAL])
    
    def _extract_validation_issues(self, error_message: str) -> str:
        """Extract specific validation issues from error message"""
        
        # Common validation patterns
        patterns = {
            r'required': "Please fill in all required fields.",
            r'invalid.*email': "Please enter a valid email address.",
            r'password.*too.*short': "Password must be longer.",
            r'invalid.*phone': "Please enter a valid phone number.",
            r'already.*exists': "This information is already in use.",
            r'must.*be.*unique': "This value must be unique.",
        }
        
        for pattern, friendly_message in patterns.items():
            if re.search(pattern, error_message, re.IGNORECASE):
                return friendly_message
        
        return "Please verify the information is correct and complete."
    
    def _get_feature_display_name(self, feature: str) -> str:
        """Get user-friendly feature name"""
        
        display_names = {
            'authentication': 'login',
            'deal_management': 'deal information',
            'payment_processing': 'payment',
            'client_management': 'client information',
            'reporting': 'report',
            'user_management': 'user account',
            'dashboard': 'dashboard'
        }
        
        return display_names.get(feature, feature)
    
    def _generate_actions(self, error_type: str, error_context: Dict, user_context: Dict) -> List[UserAction]:
        """Generate appropriate user actions"""
        
        actions = []
        
        # Error-specific actions
        if error_type == 'ValidationError':
            actions.append(UserAction(
                type=ActionType.CHECK_INPUT,
                label=_("Review Information"),
                description=_("Check and correct the highlighted fields"),
                primary=True
            ))
            
        elif error_type == 'PermissionDenied':
            actions.append(UserAction(
                type=ActionType.CONTACT_SUPPORT,
                label=_("Request Access"),
                description=_("Contact your administrator for access"),
                url="/contact-admin",
                primary=True
            ))
            
        elif error_type == 'DatabaseError':
            actions.append(UserAction(
                type=ActionType.WAIT,
                label=_("Try Again Later"),
                description=_("Wait a few minutes and try again"),
                primary=True
            ))
            
            actions.append(UserAction(
                type=ActionType.CONTACT_SUPPORT,
                label=_("Contact Support"),
                description=_("If the problem persists, contact our support team"),
                url="/support",
                icon="support"
            ))
        
        # Always add retry option if appropriate
        if error_context.get('recovery_difficulty') in ['easy', 'moderate']:
            actions.append(UserAction(
                type=ActionType.RETRY,
                label=_("Try Again"),
                description=_("Retry the same action"),
                icon="refresh"
            ))
        
        return actions
    
    def _get_relevant_help_resources(self, feature: str) -> List[HelpResource]:
        """Get relevant help resources for the feature"""
        
        feature_resources = self.help_resources.get(feature, [])
        
        # Add general help resources
        general_resources = [
            HelpResource(
                title=_("Contact Support"),
                url="/support",
                type="support",
                description=_("Get help from our support team")
            ),
            HelpResource(
                title=_("FAQ"),
                url="/faq",
                type="faq",
                description=_("Frequently asked questions")
            )
        ]
        
        return feature_resources + general_resources
    
    def _estimate_resolution_time(self, error_context: Dict) -> Optional[str]:
        """Estimate resolution time based on error context"""
        
        complexity = error_context.get('complexity_level', 'moderate')
        category = error_context.get('error_category', 'unknown')
        
        time_estimates = {
            'input_validation': "immediate",
            'access_control': "contact administrator",
            'system_issue': "5-15 minutes",
            'performance': "1-5 minutes",
            'connectivity': "check connection"
        }
        
        if category in time_estimates:
            return time_estimates[category]
        
        if complexity == 'simple':
            return "immediate"
        elif complexity == 'complex':
            return "15-30 minutes"
        else:
            return "5-15 minutes"
    
    def _determine_severity(self, error_type: str, error_context: Dict) -> str:
        """Determine message severity"""
        
        severity_map = {
            'ValidationError': 'warning',
            'PermissionDenied': 'warning',
            'DatabaseError': 'error',
            'SystemError': 'critical',
            'TimeoutError': 'warning',
            'ConnectionError': 'error'
        }
        
        base_severity = severity_map.get(error_type, 'error')
        
        # Upgrade severity based on business impact
        if error_context.get('business_impact') == 'high':
            if base_severity == 'warning':
                return 'error'
            elif base_severity == 'error':
                return 'critical'
        
        return base_severity
    
    def _add_beginner_context(self, message: str) -> str:
        """Add context for beginner users"""
        beginner_suffix = " If you need help, don't hesitate to contact our support team."
        return message + beginner_suffix
    
    def _load_message_templates(self) -> Dict[str, str]:
        """Load message templates"""
        # In a real implementation, these would be loaded from files or database
        return {
            'default': _("An unexpected error occurred. Please try again or contact support if the problem persists."),
            'ValidationError_professional': _("Please review and correct the highlighted information."),
            'ValidationError_friendly': _("Let's fix those details and try again!"),
            # Add more templates as needed
        }
    
    def _load_action_templates(self) -> Dict[str, UserAction]:
        """Load action templates"""
        return {
            'retry': UserAction(
                type=ActionType.RETRY,
                label=_("Try Again"),
                description=_("Retry the same action"),
                icon="refresh"
            ),
            'support': UserAction(
                type=ActionType.CONTACT_SUPPORT,
                label=_("Contact Support"),
                description=_("Get help from our support team"),
                url="/support",
                icon="support"
            )
        }
    
    def _load_help_resources(self) -> Dict[str, List[HelpResource]]:
        """Load help resources by feature"""
        return {
            'authentication': [
                HelpResource(
                    title=_("Login Help"),
                    url="/help/login",
                    type="documentation",
                    description=_("Help with login issues")
                )
            ],
            'deal_management': [
                HelpResource(
                    title=_("Deal Management Guide"),
                    url="/help/deals",
                    type="documentation",
                    description=_("Complete guide to managing deals")
                )
            ]
        }


# Global message generator
message_generator = MessageGenerator()


# Convenience functions
def generate_user_friendly_error(error: Exception, user_id: int = None, 
                                request_path: str = None, method: str = None,
                                tone: MessageTone = MessageTone.PROFESSIONAL) -> UserFriendlyMessage:
    """Generate user-friendly error message"""
    
    user_context = message_generator.context_analyzer.analyze_user_context(user_id)
    error_context = message_generator.context_analyzer.analyze_error_context(error, request_path, method)
    
    return message_generator.generate_message(error, user_context, error_context, tone)


def get_error_actions(error: Exception) -> List[UserAction]:
    """Get suggested actions for an error"""
    message = generate_user_friendly_error(error)
    return message.actions


def get_help_resources(feature: str) -> List[HelpResource]:
    """Get help resources for a feature"""
    return message_generator._get_relevant_help_resources(feature)
