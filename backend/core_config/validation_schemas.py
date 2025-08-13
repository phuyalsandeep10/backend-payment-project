"""
Validation schemas for API endpoints
Defines validation rules for different data types and endpoints
"""

from typing import Dict, Any

class ValidationSchemas:
    """
    Centralized validation schemas for all API endpoints
    """
    
    # User-related schemas
    USER_REGISTRATION_SCHEMA = {
        'email': {
            'type': 'email',
            'required': True,
            'max_length': 254,
            'min_length': 5
        },
        'password': {
            'type': 'password',
            'required': True,
            'max_length': 128,
            'min_length': 12,
            'check_commands': False  # Passwords can contain special chars
        },
        'first_name': {
            'type': 'string',
            'required': True,
            'max_length': 150,
            'min_length': 1
        },
        'last_name': {
            'type': 'string',
            'required': True,
            'max_length': 150,
            'min_length': 1
        },
        'contact_number': {
            'type': 'phone',
            'required': False,
            'max_length': 30
        },
        'address': {
            'type': 'string',
            'required': False,
            'max_length': 500,
            'allow_html': False
        }
    }
    
    USER_UPDATE_SCHEMA = {
        'first_name': {
            'type': 'string',
            'required': False,
            'max_length': 150,
            'min_length': 1
        },
        'last_name': {
            'type': 'string',
            'required': False,
            'max_length': 150,
            'min_length': 1
        },
        'contact_number': {
            'type': 'phone',
            'required': False,
            'max_length': 30
        },
        'address': {
            'type': 'string',
            'required': False,
            'max_length': 500,
            'allow_html': False
        },
        'sales_target': {
            'type': 'decimal',
            'required': False,
            'max_value': 999999999.99
        }
    }
    
    # Authentication schemas
    LOGIN_SCHEMA = {
        'email': {
            'type': 'email',
            'required': True,
            'max_length': 254
        },
        'password': {
            'type': 'password',
            'required': True,
            'max_length': 128,
            'check_commands': False
        }
    }
    
    PASSWORD_CHANGE_SCHEMA = {
        'current_password': {
            'type': 'password',
            'required': True,
            'max_length': 128,
            'check_commands': False
        },
        'new_password': {
            'type': 'password',
            'required': True,
            'max_length': 128,
            'min_length': 12,
            'check_commands': False
        },
        'confirm_password': {
            'type': 'password',
            'required': True,
            'max_length': 128,
            'check_commands': False
        }
    }
    
    OTP_SCHEMA = {
        'email': {
            'type': 'email',
            'required': True,
            'max_length': 254
        },
        'otp': {
            'type': 'string',
            'required': True,
            'max_length': 6,
            'min_length': 6,
            'pattern': r'^\d{6}$'
        }
    }
    
    # Client-related schemas
    CLIENT_CREATE_SCHEMA = {
        'client_name': {
            'type': 'string',
            'required': True,
            'max_length': 255,
            'min_length': 2
        },
        'email': {
            'type': 'email',
            'required': True,
            'max_length': 254
        },
        'phone_number': {
            'type': 'phone',
            'required': True,
            'max_length': 30
        },
        'nationality': {
            'type': 'string',
            'required': False,
            'max_length': 100
        },
        'remarks': {
            'type': 'string',
            'required': False,
            'max_length': 1000,
            'allow_html': False
        },
        'satisfaction': {
            'type': 'choice',
            'required': False,
            'choices': ['neutral', 'satisfied', 'unsatisfied']
        },
        'status': {
            'type': 'choice',
            'required': False,
            'choices': ['pending', 'bad_debt', 'clear']
        }
    }
    
    CLIENT_UPDATE_SCHEMA = CLIENT_CREATE_SCHEMA.copy()
    # Make all fields optional for updates
    for field in CLIENT_UPDATE_SCHEMA:
        CLIENT_UPDATE_SCHEMA[field]['required'] = False
    
    # Deal-related schemas
    DEAL_CREATE_SCHEMA = {
        'deal_name': {
            'type': 'string',
            'required': True,
            'max_length': 255,
            'min_length': 2
        },
        'deal_value': {
            'type': 'decimal',
            'required': True,
            'min_value': 0.01,
            'max_value': 999999999.9999
        },
        'currency': {
            'type': 'string',
            'required': False,
            'max_length': 3,
            'pattern': r'^[A-Z]{3}$'
        },
        'payment_status': {
            'type': 'choice',
            'required': True,
            'choices': ['initial payment', 'partial_payment', 'full_payment']
        },
        'payment_method': {
            'type': 'choice',
            'required': True,
            'choices': ['wallet', 'bank', 'cheque', 'cash']
        },
        'source_type': {
            'type': 'choice',
            'required': True,
            'choices': ['linkedin', 'instagram', 'google', 'referral', 'others']
        },
        'deal_remarks': {
            'type': 'string',
            'required': False,
            'max_length': 1000,
            'allow_html': False
        },
        'client_status': {
            'type': 'choice',
            'required': False,
            'choices': ['pending', 'loyal', 'bad_debt']
        }
    }
    
    DEAL_UPDATE_SCHEMA = DEAL_CREATE_SCHEMA.copy()
    # Make all fields optional for updates
    for field in DEAL_UPDATE_SCHEMA:
        DEAL_UPDATE_SCHEMA[field]['required'] = False
    
    # Payment-related schemas
    PAYMENT_CREATE_SCHEMA = {
        'received_amount': {
            'type': 'decimal',
            'required': True,
            'min_value': 0.01,
            'max_value': 999999999.99
        },
        'payment_type': {
            'type': 'choice',
            'required': True,
            'choices': ['wallet', 'bank', 'cheque', 'cash']
        },
        'payment_category': {
            'type': 'choice',
            'required': False,
            'choices': ['advance', 'partial', 'final']
        },
        'cheque_number': {
            'type': 'string',
            'required': False,
            'max_length': 50,
            'pattern': r'^[A-Za-z0-9\-_]+$'
        },
        'payment_remarks': {
            'type': 'string',
            'required': False,
            'max_length': 1000,
            'allow_html': False
        }
    }
    
    # Organization-related schemas
    ORGANIZATION_CREATE_SCHEMA = {
        'name': {
            'type': 'string',
            'required': True,
            'max_length': 255,
            'min_length': 2
        },
        'description': {
            'type': 'string',
            'required': False,
            'max_length': 1000,
            'allow_html': False
        }
    }
    
    # Team-related schemas
    TEAM_CREATE_SCHEMA = {
        'name': {
            'type': 'string',
            'required': True,
            'max_length': 255,
            'min_length': 2
        },
        'description': {
            'type': 'string',
            'required': False,
            'max_length': 500,
            'allow_html': False
        }
    }
    
    # Search and filter schemas
    SEARCH_SCHEMA = {
        'q': {
            'type': 'string',
            'required': False,
            'max_length': 255,
            'min_length': 1
        },
        'page': {
            'type': 'integer',
            'required': False,
            'min_value': 1,
            'max_value': 10000
        },
        'limit': {
            'type': 'integer',
            'required': False,
            'min_value': 1,
            'max_value': 100
        },
        'ordering': {
            'type': 'string',
            'required': False,
            'max_length': 100,
            'pattern': r'^-?[a-zA-Z_][a-zA-Z0-9_]*$'
        }
    }
    
    @classmethod
    def get_schema(cls, schema_name: str) -> Dict[str, Any]:
        """Get validation schema by name"""
        return getattr(cls, schema_name, {})
    
    @classmethod
    def get_endpoint_schema(cls, endpoint: str, method: str) -> Dict[str, Any]:
        """Get validation schema for specific endpoint and method"""
        schema_map = {
            # Authentication endpoints
            ('auth/login', 'POST'): cls.LOGIN_SCHEMA,
            ('auth/register', 'POST'): cls.USER_REGISTRATION_SCHEMA,
            ('auth/password/change', 'POST'): cls.PASSWORD_CHANGE_SCHEMA,
            ('auth/verify-otp', 'POST'): cls.OTP_SCHEMA,
            
            # User endpoints
            ('auth/users', 'POST'): cls.USER_REGISTRATION_SCHEMA,
            ('auth/users', 'PUT'): cls.USER_UPDATE_SCHEMA,
            ('auth/users', 'PATCH'): cls.USER_UPDATE_SCHEMA,
            ('auth/profile', 'PUT'): cls.USER_UPDATE_SCHEMA,
            ('auth/profile', 'PATCH'): cls.USER_UPDATE_SCHEMA,
            
            # Client endpoints
            ('clients', 'POST'): cls.CLIENT_CREATE_SCHEMA,
            ('clients', 'PUT'): cls.CLIENT_UPDATE_SCHEMA,
            ('clients', 'PATCH'): cls.CLIENT_UPDATE_SCHEMA,
            
            # Deal endpoints
            ('deals/deals', 'POST'): cls.DEAL_CREATE_SCHEMA,
            ('deals/deals', 'PUT'): cls.DEAL_UPDATE_SCHEMA,
            ('deals/deals', 'PATCH'): cls.DEAL_UPDATE_SCHEMA,
            
            # Payment endpoints
            ('deals/payments', 'POST'): cls.PAYMENT_CREATE_SCHEMA,
            
            # Organization endpoints
            ('organization', 'POST'): cls.ORGANIZATION_CREATE_SCHEMA,
            
            # Team endpoints
            ('team/teams', 'POST'): cls.TEAM_CREATE_SCHEMA,
        }
        
        # Normalize endpoint path
        endpoint = endpoint.strip('/')
        key = (endpoint, method.upper())
        
        return schema_map.get(key, {})