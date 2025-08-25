"""
Validation Schemas for API Endpoints

This module defines validation schemas for all API endpoints
to ensure consistent input validation across the application.
"""

from typing import Dict, Any

# Common field schemas
COMMON_SCHEMAS = {
    'email': {
        'type': 'string',
        'required': True,
        'pattern': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'max_length': 254,
        'strip_html': True
    },
    'password': {
        'type': 'string',
        'required': True,
        'min_length': 8,
        'max_length': 128,
        'strip_html': True
    },
    'phone': {
        'type': 'string',
        'pattern': r'^\+?1?\d{9,15}$',
        'max_length': 20,
        'strip_html': True
    },
    'name': {
        'type': 'string',
        'required': True,
        'min_length': 1,
        'max_length': 100,
        'strip_html': True
    },
    'description': {
        'type': 'string',
        'max_length': 1000,
        'allow_html': False,
        'strip_html': True
    },
    'currency_amount': {
        'type': 'string',
        'pattern': r'^\d+(\.\d{1,4})?$',
        'max_length': 20
    },
    'id': {
        'type': 'integer',
        'min_value': 1
    },
    'uuid': {
        'type': 'string',
        'pattern': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    },
    'date': {
        'type': 'string',
        'pattern': r'^\d{4}-\d{2}-\d{2}$'
    },
    'datetime': {
        'type': 'string',
        'pattern': r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z?$'
    },
    'url': {
        'type': 'string',
        'pattern': r'^https?://[^\s/$.?#].[^\s]*$',
        'max_length': 2048
    }
}

# Authentication schemas
AUTH_SCHEMAS = {
    'login': {
        'email': COMMON_SCHEMAS['email'],
        'password': COMMON_SCHEMAS['password'],
        'remember_me': {
            'type': 'boolean',
            'required': False
        }
    },
    'register': {
        'email': COMMON_SCHEMAS['email'],
        'password': COMMON_SCHEMAS['password'],
        'first_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'last_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'terms_accepted': {
            'type': 'boolean',
            'required': True
        }
    },
    'password_reset_request': {
        'email': COMMON_SCHEMAS['email']
    },
    'password_reset_confirm': {
        'token': {
            'type': 'string',
            'required': True,
            'min_length': 20,
            'max_length': 100,
            'strip_html': True
        },
        'new_password': COMMON_SCHEMAS['password']
    },
    'change_password': {
        'current_password': COMMON_SCHEMAS['password'],
        'new_password': COMMON_SCHEMAS['password']
    },
    'otp_verify': {
        'otp': {
            'type': 'string',
            'required': True,
            'pattern': r'^\d{6}$',
            'strip_html': True
        },
        'purpose': {
            'type': 'string',
            'required': True,
            'allowed_values': ['LOGIN', 'PASSWORD_RESET', 'ACCOUNT_VERIFICATION'],
            'strip_html': True
        }
    }
}

# User management schemas
USER_SCHEMAS = {
    'profile_update': {
        'first_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50,
            'required': False
        },
        'last_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50,
            'required': False
        },
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'bio': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        }
    },
    'user_create': {
        'email': COMMON_SCHEMAS['email'],
        'first_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'last_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'role': {
            'type': 'string',
            'required': True,
            'allowed_values': ['ADMIN', 'MANAGER', 'USER'],
            'strip_html': True
        },
        'organization_id': COMMON_SCHEMAS['id']
    }
}

# Deal management schemas
DEAL_SCHEMAS = {
    'deal_create': {
        'title': {
            **COMMON_SCHEMAS['name'],
            'max_length': 200
        },
        'description': COMMON_SCHEMAS['description'],
        'deal_value': COMMON_SCHEMAS['currency_amount'],
        'currency': {
            'type': 'string',
            'required': True,
            'allowed_values': ['USD', 'EUR', 'GBP', 'CAD', 'AUD'],
            'strip_html': True
        },
        'client_id': COMMON_SCHEMAS['id'],
        'expected_close_date': COMMON_SCHEMAS['date'],
        'deal_type': {
            'type': 'string',
            'required': True,
            'allowed_values': ['NEW_BUSINESS', 'EXISTING_BUSINESS', 'RENEWAL'],
            'strip_html': True
        }
    },
    'deal_update': {
        'title': {
            **COMMON_SCHEMAS['name'],
            'max_length': 200,
            'required': False
        },
        'description': {
            **COMMON_SCHEMAS['description'],
            'required': False
        },
        'deal_value': {
            **COMMON_SCHEMAS['currency_amount'],
            'required': False
        },
        'status': {
            'type': 'string',
            'allowed_values': ['DRAFT', 'ACTIVE', 'WON', 'LOST', 'CANCELLED'],
            'strip_html': True,
            'required': False
        },
        'expected_close_date': {
            **COMMON_SCHEMAS['date'],
            'required': False
        }
    },
    'payment_create': {
        'deal_id': COMMON_SCHEMAS['id'],
        'amount': COMMON_SCHEMAS['currency_amount'],
        'payment_method': {
            'type': 'string',
            'required': True,
            'allowed_values': ['CREDIT_CARD', 'BANK_TRANSFER', 'CHECK', 'CASH'],
            'strip_html': True
        },
        'reference_number': {
            'type': 'string',
            'max_length': 100,
            'required': False,
            'strip_html': True
        },
        'notes': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        }
    }
}

# File upload schemas
FILE_SCHEMAS = {
    'file_upload': {
        'file_type': {
            'type': 'string',
            'required': True,
            'allowed_values': ['DOCUMENT', 'IMAGE', 'SPREADSHEET', 'PDF'],
            'strip_html': True
        },
        'description': {
            **COMMON_SCHEMAS['description'],
            'required': False
        },
        'is_public': {
            'type': 'boolean',
            'required': False
        }
    },
    'bulk_upload': {
        'file_type': {
            'type': 'string',
            'required': True,
            'allowed_values': ['CSV', 'XLSX', 'JSON'],
            'strip_html': True
        },
        'entity_type': {
            'type': 'string',
            'required': True,
            'allowed_values': ['DEALS', 'CLIENTS', 'PAYMENTS'],
            'strip_html': True
        },
        'overwrite_existing': {
            'type': 'boolean',
            'required': False
        }
    }
}

# Organization schemas
ORGANIZATION_SCHEMAS = {
    'organization_create': {
        'name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 200
        },
        'description': COMMON_SCHEMAS['description'],
        'website': {
            **COMMON_SCHEMAS['url'],
            'required': False
        },
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'address': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        }
    },
    'organization_update': {
        'name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 200,
            'required': False
        },
        'description': {
            **COMMON_SCHEMAS['description'],
            'required': False
        },
        'website': {
            **COMMON_SCHEMAS['url'],
            'required': False
        },
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'address': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        }
    }
}

# Client schemas
CLIENT_SCHEMAS = {
    'client_create': {
        'first_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'last_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50
        },
        'email': COMMON_SCHEMAS['email'],
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'company': {
            'type': 'string',
            'max_length': 200,
            'required': False,
            'strip_html': True
        },
        'address': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        },
        'notes': {
            'type': 'string',
            'max_length': 1000,
            'required': False,
            'strip_html': True
        }
    },
    'client_update': {
        'first_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50,
            'required': False
        },
        'last_name': {
            **COMMON_SCHEMAS['name'],
            'max_length': 50,
            'required': False
        },
        'email': {
            **COMMON_SCHEMAS['email'],
            'required': False
        },
        'phone': {
            **COMMON_SCHEMAS['phone'],
            'required': False
        },
        'company': {
            'type': 'string',
            'max_length': 200,
            'required': False,
            'strip_html': True
        },
        'address': {
            'type': 'string',
            'max_length': 500,
            'required': False,
            'strip_html': True
        },
        'notes': {
            'type': 'string',
            'max_length': 1000,
            'required': False,
            'strip_html': True
        }
    }
}

# Search and filter schemas
SEARCH_SCHEMAS = {
    'search': {
        'query': {
            'type': 'string',
            'required': True,
            'min_length': 1,
            'max_length': 200,
            'strip_html': True
        },
        'entity_type': {
            'type': 'string',
            'allowed_values': ['DEALS', 'CLIENTS', 'ORGANIZATIONS', 'ALL'],
            'required': False,
            'strip_html': True
        },
        'limit': {
            'type': 'integer',
            'min_value': 1,
            'max_value': 100,
            'required': False
        },
        'offset': {
            'type': 'integer',
            'min_value': 0,
            'required': False
        }
    },
    'filter': {
        'date_from': {
            **COMMON_SCHEMAS['date'],
            'required': False
        },
        'date_to': {
            **COMMON_SCHEMAS['date'],
            'required': False
        },
        'status': {
            'type': 'string',
            'allowed_values': ['DRAFT', 'ACTIVE', 'WON', 'LOST', 'CANCELLED'],
            'required': False,
            'strip_html': True
        },
        'min_value': {
            **COMMON_SCHEMAS['currency_amount'],
            'required': False
        },
        'max_value': {
            **COMMON_SCHEMAS['currency_amount'],
            'required': False
        }
    }
}

# Report schemas
REPORT_SCHEMAS = {
    'report_generate': {
        'report_type': {
            'type': 'string',
            'required': True,
            'allowed_values': ['SALES', 'PAYMENTS', 'CLIENTS', 'PERFORMANCE'],
            'strip_html': True
        },
        'date_from': COMMON_SCHEMAS['date'],
        'date_to': COMMON_SCHEMAS['date'],
        'format': {
            'type': 'string',
            'allowed_values': ['PDF', 'CSV', 'XLSX'],
            'required': False,
            'strip_html': True
        },
        'include_details': {
            'type': 'boolean',
            'required': False
        }
    }
}

# Combine all schemas
ALL_SCHEMAS = {
    **AUTH_SCHEMAS,
    **USER_SCHEMAS,
    **DEAL_SCHEMAS,
    **FILE_SCHEMAS,
    **ORGANIZATION_SCHEMAS,
    **CLIENT_SCHEMAS,
    **SEARCH_SCHEMAS,
    **REPORT_SCHEMAS
}


def get_schema(endpoint_name: str) -> Dict[str, Any]:
    """
    Get validation schema for a specific endpoint
    
    Args:
        endpoint_name: Name of the endpoint
        
    Returns:
        Validation schema dictionary
    """
    return ALL_SCHEMAS.get(endpoint_name, {})


def get_all_schemas() -> Dict[str, Dict[str, Any]]:
    """
    Get all validation schemas
    
    Returns:
        Dictionary of all schemas
    """
    return ALL_SCHEMAS